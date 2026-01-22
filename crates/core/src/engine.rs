use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::constants::{NONE_ORDER_ID, NONE_TICK};
use crate::errors::CoreError;
use crate::input::{Message, Rules, SignedMessage};
use crate::math::{mul_div_down, mul_div_up};
use crate::state::{
    get_balance, get_fee_vault, get_market_best, get_nonce, get_order, get_order_node, get_tick_node,
    set_balance, set_fee_vault, set_market_best, set_nonce, set_order, set_order_node, set_tick_node,
    StateAccess,
};
use crate::types::{Balance, FeeTotal, MarketBest, Order, OrderNode, OrderStatus, Side, TickNode, TimeInForce, TradeRecord, U256};
use crate::verify::{check_lot_size, verify_signature, price_from_tick};

pub struct BatchOutput {
    pub trades: Vec<TradeRecord>,
    pub fee_totals: Vec<FeeTotal>,
}

pub fn apply_batch<S: StateAccess>(
    state: &mut S,
    market_id: [u8; 32],
    rules: &Rules,
    domain_sep: [u8; 32],
    messages: &[SignedMessage],
) -> Result<BatchOutput, CoreError> {
    if messages.len() > rules.max_orders_per_batch as usize {
        return Err(CoreError::Invalid("maxOrdersPerBatch exceeded"));
    }
    if rules.price_scale != U256::from(1_000_000_000_000_000_000u128) {
        return Err(CoreError::Invalid("priceScale must be 1e18"));
    }
    if rules.maker_fee_bps != 0 {
        return Err(CoreError::Invalid("makerFeeBps must be zero"));
    }

    let mut trades = Vec::new();
    let mut fee_totals: BTreeMap<[u8; 32], U256> = BTreeMap::new();

    for signed in messages {
        let message = &signed.message;
        let trader = match message {
            Message::Place { trader, .. } => trader,
            Message::Cancel { trader, .. } => trader,
        };
        verify_signature(&domain_sep, message, &signed.signature, trader)?;
        let nonce_value = match message {
            Message::Place { nonce, .. } => *nonce,
            Message::Cancel { nonce, .. } => *nonce,
        };
        let current_nonce = get_nonce(state, trader)?;
        if nonce_value != current_nonce + 1 {
            return Err(CoreError::Invalid("nonce mismatch"));
        }
        set_nonce(state, trader, nonce_value)?;

        match message {
            Message::Place {
                trader,
                order_id,
                side,
                tif,
                tick_index,
                qty_base,
                prev_tick_hint,
                next_tick_hint,
                ..
            } => {
                if get_order(state, order_id)?.is_some() {
                    return Err(CoreError::Invalid("order id already exists"));
                }
                if qty_base.is_zero() {
                    return Err(CoreError::Invalid("qtyBase zero"));
                }
                check_lot_size(*qty_base, rules.lot_size)?;
                let price = price_from_tick(*tick_index, rules.tick_size)?;
                let mut remaining = *qty_base;
                let limit_price = price;

                let mut balance_quote = get_balance(state, trader, &rules.quote_asset_id)?;
                let mut balance_base = get_balance(state, trader, &rules.base_asset_id)?;

                match side {
                    Side::Buy => {
                        let lock_quote = mul_div_up(price, *qty_base, rules.price_scale)?;
                        if balance_quote.available < lock_quote {
                            return Err(CoreError::Invalid("insufficient quote balance"));
                        }
                        balance_quote.available -= lock_quote;
                        balance_quote.locked += lock_quote;
                        set_balance(state, trader, &rules.quote_asset_id, &balance_quote)?;
                    }
                    Side::Sell => {
                        if balance_base.available < *qty_base {
                            return Err(CoreError::Invalid("insufficient base balance"));
                        }
                        balance_base.available -= *qty_base;
                        balance_base.locked += *qty_base;
                        set_balance(state, trader, &rules.base_asset_id, &balance_base)?;
                    }
                }

                let mut best = get_market_best(state, &market_id)?;
                let mut matches = 0u32;

                loop {
                    let current_tick = match side {
                        Side::Buy => best.best_ask,
                        Side::Sell => best.best_bid,
                    };
                    if current_tick == NONE_TICK {
                        break;
                    }
                    let tick_price = price_from_tick(current_tick, rules.tick_size)?;
                    let price_ok = match side {
                        Side::Buy => tick_price <= limit_price,
                        Side::Sell => tick_price >= limit_price,
                    };
                    if !price_ok || remaining.is_zero() {
                        break;
                    }

                    let mut tick_node = get_tick_node(state, &market_id, side.opposite().as_u8(), current_tick)?;
                    while tick_node.head_order_id != NONE_ORDER_ID && !remaining.is_zero() {
                        if matches >= rules.max_matches_per_order {
                            return Err(CoreError::Invalid("maxMatchesPerOrder exceeded"));
                        }
                        matches += 1;
                        let maker_order_id = tick_node.head_order_id;
                        let mut maker_order = get_order(state, &maker_order_id)?
                            .ok_or(CoreError::Invalid("maker order missing"))?;
                        if maker_order.status != OrderStatus::Open {
                            return Err(CoreError::Invalid("maker order not open"));
                        }
                        if maker_order.side == *side {
                            return Err(CoreError::Invalid("maker side mismatch"));
                        }
                        let fill_qty = if remaining < maker_order.qty_remaining {
                            remaining
                        } else {
                            maker_order.qty_remaining
                        };
                        let quote_amt = mul_div_down(tick_price, fill_qty, rules.price_scale)?;
                        let fee = mul_div_up(quote_amt, U256::from(rules.taker_fee_bps), U256::from(10_000u64))?;

                        match side {
                            Side::Buy => {
                                let mut taker_quote = get_balance(state, trader, &rules.quote_asset_id)?;
                                let mut taker_base = get_balance(state, trader, &rules.base_asset_id)?;
                                let mut maker_base = get_balance(state, &maker_order.owner, &rules.base_asset_id)?;
                                let mut maker_quote = get_balance(state, &maker_order.owner, &rules.quote_asset_id)?;

                                let spend = quote_amt + fee;
                                if taker_quote.locked < spend {
                                    return Err(CoreError::Invalid("taker locked quote insufficient"));
                                }
                                if maker_base.locked < fill_qty {
                                    return Err(CoreError::Invalid("maker locked base insufficient"));
                                }

                                taker_quote.locked -= spend;
                                taker_base.available += fill_qty;
                                maker_base.locked -= fill_qty;
                                maker_quote.available += quote_amt;

                                ensure_balance_limit(&taker_quote, rules.max_balance)?;
                                ensure_balance_limit(&taker_base, rules.max_balance)?;
                                ensure_balance_limit(&maker_base, rules.max_balance)?;
                                ensure_balance_limit(&maker_quote, rules.max_balance)?;

                                set_balance(state, trader, &rules.quote_asset_id, &taker_quote)?;
                                set_balance(state, trader, &rules.base_asset_id, &taker_base)?;
                                set_balance(state, &maker_order.owner, &rules.base_asset_id, &maker_base)?;
                                set_balance(state, &maker_order.owner, &rules.quote_asset_id, &maker_quote)?;
                            }
                            Side::Sell => {
                                let mut taker_base = get_balance(state, trader, &rules.base_asset_id)?;
                                let mut taker_quote = get_balance(state, trader, &rules.quote_asset_id)?;
                                let mut maker_base = get_balance(state, &maker_order.owner, &rules.base_asset_id)?;
                                let mut maker_quote = get_balance(state, &maker_order.owner, &rules.quote_asset_id)?;

                                if taker_base.locked < fill_qty {
                                    return Err(CoreError::Invalid("taker locked base insufficient"));
                                }
                                if maker_quote.locked < quote_amt {
                                    return Err(CoreError::Invalid("maker locked quote insufficient"));
                                }

                                taker_base.locked -= fill_qty;
                                let receive = quote_amt.checked_sub(fee).ok_or(CoreError::Math("fee exceeds quote"))?;
                                taker_quote.available += receive;
                                maker_quote.locked -= quote_amt;
                                maker_base.available += fill_qty;

                                ensure_balance_limit(&taker_base, rules.max_balance)?;
                                ensure_balance_limit(&taker_quote, rules.max_balance)?;
                                ensure_balance_limit(&maker_base, rules.max_balance)?;
                                ensure_balance_limit(&maker_quote, rules.max_balance)?;

                                set_balance(state, trader, &rules.base_asset_id, &taker_base)?;
                                set_balance(state, trader, &rules.quote_asset_id, &taker_quote)?;
                                set_balance(state, &maker_order.owner, &rules.base_asset_id, &maker_base)?;
                                set_balance(state, &maker_order.owner, &rules.quote_asset_id, &maker_quote)?;
                            }
                        }

                        let fee_asset = rules.quote_asset_id;
                        let entry = fee_totals.entry(fee_asset).or_insert_with(U256::zero);
                        *entry += fee;
                        let mut fee_vault = get_fee_vault(state, &fee_asset)?;
                        fee_vault.total += fee;
                        set_fee_vault(state, &fee_asset, &fee_vault)?;

                        maker_order.qty_remaining -= fill_qty;
                        if maker_order.qty_remaining.is_zero() {
                            maker_order.status = OrderStatus::Filled;
                        }
                        set_order(state, &maker_order_id, &maker_order)?;

                        trades.push(TradeRecord {
                            market_id,
                            maker_order_id,
                            taker_order_id: *order_id,
                            maker: maker_order.owner,
                            taker: *trader,
                            side_taker: *side,
                            maker_tick: maker_order.tick,
                            qty_base: fill_qty,
                            quote_amt,
                            taker_fee_quote: fee,
                        });

                        remaining -= fill_qty;

                        if maker_order.status == OrderStatus::Filled {
                            let maker_node = get_order_node(state, &maker_order_id)?;
                            let next_id = maker_node.next_order_id;
                            tick_node.head_order_id = next_id;
                            if next_id == NONE_ORDER_ID {
                                tick_node.tail_order_id = NONE_ORDER_ID;
                            } else {
                                let mut next_node = get_order_node(state, &next_id)?;
                                next_node.prev_order_id = NONE_ORDER_ID;
                                set_order_node(state, &next_id, &next_node)?;
                            }
                            set_order_node(state, &maker_order_id, &OrderNode {
                                prev_order_id: NONE_ORDER_ID,
                                next_order_id: NONE_ORDER_ID,
                            })?;
                        }
                    }

                    if tick_node.head_order_id == NONE_ORDER_ID {
                        let prev_tick = tick_node.prev_tick;
                        let next_tick = tick_node.next_tick;
                        if prev_tick != NONE_TICK {
                            let mut prev_node = get_tick_node(state, &market_id, side.opposite().as_u8(), prev_tick)?;
                            prev_node.next_tick = next_tick;
                            set_tick_node(state, &market_id, side.opposite().as_u8(), prev_tick, &prev_node)?;
                        }
                        if next_tick != NONE_TICK {
                            let mut next_node = get_tick_node(state, &market_id, side.opposite().as_u8(), next_tick)?;
                            next_node.prev_tick = prev_tick;
                            set_tick_node(state, &market_id, side.opposite().as_u8(), next_tick, &next_node)?;
                        }
                        match side {
                            Side::Buy => {
                                if best.best_ask == current_tick {
                                    best.best_ask = next_tick;
                                }
                            }
                            Side::Sell => {
                                if best.best_bid == current_tick {
                                    best.best_bid = next_tick;
                                }
                            }
                        }
                        set_tick_node(
                            state,
                            &market_id,
                            side.opposite().as_u8(),
                            current_tick,
                            &TickNode {
                                prev_tick: NONE_TICK,
                                next_tick: NONE_TICK,
                                head_order_id: NONE_ORDER_ID,
                                tail_order_id: NONE_ORDER_ID,
                            },
                        )?;
                        set_market_best(state, &market_id, &best)?;
                    } else {
                        set_tick_node(state, &market_id, side.opposite().as_u8(), current_tick, &tick_node)?;
                    }

                    if remaining.is_zero() {
                        break;
                    }
                }

                match tif {
                    TimeInForce::Ioc => {
                        if !remaining.is_zero() {
                            release_remaining(
                                state,
                                trader,
                                *side,
                                remaining,
                                price,
                                rules,
                            )?;
                        }
                        set_order(
                            state,
                            order_id,
                            &Order {
                                owner: *trader,
                                side: *side,
                                tick: *tick_index,
                                qty_remaining: U256::zero(),
                                tif: *tif,
                                status: if remaining.is_zero() {
                                    OrderStatus::Filled
                                } else {
                                    OrderStatus::Canceled
                                },
                            },
                        )?;
                    }
                    TimeInForce::Gtc => {
                        if remaining.is_zero() {
                            set_order(
                                state,
                                order_id,
                                &Order {
                                    owner: *trader,
                                    side: *side,
                                    tick: *tick_index,
                                    qty_remaining: U256::zero(),
                                    tif: *tif,
                                    status: OrderStatus::Filled,
                                },
                            )?;
                        } else {
                            place_resting(
                                state,
                                &market_id,
                                order_id,
                                trader,
                                *side,
                                *tick_index,
                                remaining,
                                *tif,
                                *prev_tick_hint,
                                *next_tick_hint,
                                &mut best,
                            )?;
                        }
                    }
                }
            }
            Message::Cancel { trader, order_id, .. } => {
                let mut order = get_order(state, order_id)?.ok_or(CoreError::Invalid("order missing"))?;
                if &order.owner != trader {
                    return Err(CoreError::Invalid("cancel owner mismatch"));
                }
                if order.status != OrderStatus::Open {
                    return Err(CoreError::Invalid("order not open"));
                }
                let price = price_from_tick(order.tick, rules.tick_size)?;
                release_remaining(state, trader, order.side, order.qty_remaining, price, rules)?;
                order.qty_remaining = U256::zero();
                order.status = OrderStatus::Canceled;
                set_order(state, order_id, &order)?;
                remove_from_book(state, &market_id, order.side, order.tick, order_id)?;
            }
        }
    }

    let mut fee_totals_vec = Vec::with_capacity(fee_totals.len());
    for (asset, total) in fee_totals {
        fee_totals_vec.push(FeeTotal {
            asset_id: asset,
            total_fee: total,
        });
    }

    Ok(BatchOutput {
        trades,
        fee_totals: fee_totals_vec,
    })
}

fn ensure_balance_limit(balance: &Balance, max_balance: U256) -> Result<(), CoreError> {
    if balance.available > max_balance || balance.locked > max_balance {
        return Err(CoreError::Invalid("balance exceeds maxBalance"));
    }
    Ok(())
}

fn release_remaining<S: StateAccess>(
    state: &mut S,
    trader: &[u8; 20],
    side: Side,
    remaining: U256,
    price: U256,
    rules: &Rules,
) -> Result<(), CoreError> {
    match side {
        Side::Buy => {
            let release = mul_div_up(price, remaining, rules.price_scale)?;
            let mut bal = get_balance(state, trader, &rules.quote_asset_id)?;
            if bal.locked < release {
                return Err(CoreError::Invalid("locked quote insufficient"));
            }
            bal.locked -= release;
            bal.available += release;
            ensure_balance_limit(&bal, rules.max_balance)?;
            set_balance(state, trader, &rules.quote_asset_id, &bal)?;
        }
        Side::Sell => {
            let mut bal = get_balance(state, trader, &rules.base_asset_id)?;
            if bal.locked < remaining {
                return Err(CoreError::Invalid("locked base insufficient"));
            }
            bal.locked -= remaining;
            bal.available += remaining;
            ensure_balance_limit(&bal, rules.max_balance)?;
            set_balance(state, trader, &rules.base_asset_id, &bal)?;
        }
    }
    Ok(())
}

fn place_resting<S: StateAccess>(
    state: &mut S,
    market_id: &[u8; 32],
    order_id: &[u8; 32],
    trader: &[u8; 20],
    side: Side,
    tick: i32,
    qty_remaining: U256,
    tif: TimeInForce,
    prev_tick_hint: i32,
    next_tick_hint: i32,
    best: &mut MarketBest,
) -> Result<(), CoreError> {
    let mut tick_node = get_tick_node(state, market_id, side.as_u8(), tick)?;
    let active = tick_node.head_order_id != NONE_ORDER_ID;
    let old_tail = if active {
        tick_node.tail_order_id
    } else {
        NONE_ORDER_ID
    };

    if !active {
        verify_tick_hints(state, market_id, side, tick, prev_tick_hint, next_tick_hint, best)?;
        tick_node.prev_tick = prev_tick_hint;
        tick_node.next_tick = next_tick_hint;
        tick_node.head_order_id = *order_id;
        tick_node.tail_order_id = *order_id;

        if prev_tick_hint != NONE_TICK {
            let mut prev_node = get_tick_node(state, market_id, side.as_u8(), prev_tick_hint)?;
            prev_node.next_tick = tick;
            set_tick_node(state, market_id, side.as_u8(), prev_tick_hint, &prev_node)?;
        }
        if next_tick_hint != NONE_TICK {
            let mut next_node = get_tick_node(state, market_id, side.as_u8(), next_tick_hint)?;
            next_node.prev_tick = tick;
            set_tick_node(state, market_id, side.as_u8(), next_tick_hint, &next_node)?;
        }
        match side {
            Side::Buy => {
                if best.best_bid == NONE_TICK || tick > best.best_bid {
                    best.best_bid = tick;
                }
            }
            Side::Sell => {
                if best.best_ask == NONE_TICK || tick < best.best_ask {
                    best.best_ask = tick;
                }
            }
        }
        set_market_best(state, market_id, best)?;
    } else {
        let tail_id = tick_node.tail_order_id;
        if tail_id != NONE_ORDER_ID {
            let mut tail_node = get_order_node(state, &tail_id)?;
            tail_node.next_order_id = *order_id;
            set_order_node(state, &tail_id, &tail_node)?;
        }
        tick_node.tail_order_id = *order_id;
    }

    set_tick_node(state, market_id, side.as_u8(), tick, &tick_node)?;
    set_order(
        state,
        order_id,
        &Order {
            owner: *trader,
            side,
            tick,
            qty_remaining,
            tif,
            status: OrderStatus::Open,
        },
    )?;
    set_order_node(
        state,
        order_id,
        &OrderNode {
            prev_order_id: old_tail,
            next_order_id: NONE_ORDER_ID,
        },
    )?;

    Ok(())
}

fn verify_tick_hints<S: StateAccess>(
    state: &mut S,
    market_id: &[u8; 32],
    side: Side,
    tick: i32,
    prev_tick: i32,
    next_tick: i32,
    best: &MarketBest,
) -> Result<(), CoreError> {
    if prev_tick != NONE_TICK {
        let prev_node = get_tick_node(state, market_id, side.as_u8(), prev_tick)?;
        if prev_node.next_tick != next_tick {
            return Err(CoreError::Invalid("prev tick hint mismatch"));
        }
        if side == Side::Buy && prev_tick <= tick {
            return Err(CoreError::Invalid("bid prev tick order"));
        }
        if side == Side::Sell && prev_tick >= tick {
            return Err(CoreError::Invalid("ask prev tick order"));
        }
    } else {
        match side {
            Side::Buy => {
                if best.best_bid != next_tick && best.best_bid != NONE_TICK {
                    return Err(CoreError::Invalid("best bid mismatch"));
                }
            }
            Side::Sell => {
                if best.best_ask != next_tick && best.best_ask != NONE_TICK {
                    return Err(CoreError::Invalid("best ask mismatch"));
                }
            }
        }
    }
    if next_tick != NONE_TICK {
        let next_node = get_tick_node(state, market_id, side.as_u8(), next_tick)?;
        if next_node.prev_tick != prev_tick {
            return Err(CoreError::Invalid("next tick hint mismatch"));
        }
        if side == Side::Buy && next_tick >= tick {
            return Err(CoreError::Invalid("bid next tick order"));
        }
        if side == Side::Sell && next_tick <= tick {
            return Err(CoreError::Invalid("ask next tick order"));
        }
    }
    Ok(())
}

fn remove_from_book<S: StateAccess>(
    state: &mut S,
    market_id: &[u8; 32],
    side: Side,
    tick: i32,
    order_id: &[u8; 32],
) -> Result<(), CoreError> {
    let mut tick_node = get_tick_node(state, market_id, side.as_u8(), tick)?;
    let order_node = get_order_node(state, order_id)?;
    let prev_id = order_node.prev_order_id;
    let next_id = order_node.next_order_id;

    if prev_id != NONE_ORDER_ID {
        let mut prev_node = get_order_node(state, &prev_id)?;
        prev_node.next_order_id = next_id;
        set_order_node(state, &prev_id, &prev_node)?;
    } else {
        tick_node.head_order_id = next_id;
    }
    if next_id != NONE_ORDER_ID {
        let mut next_node = get_order_node(state, &next_id)?;
        next_node.prev_order_id = prev_id;
        set_order_node(state, &next_id, &next_node)?;
    } else {
        tick_node.tail_order_id = prev_id;
    }

    set_order_node(
        state,
        order_id,
        &OrderNode {
            prev_order_id: NONE_ORDER_ID,
            next_order_id: NONE_ORDER_ID,
        },
    )?;

    if tick_node.head_order_id == NONE_ORDER_ID {
        let prev_tick = tick_node.prev_tick;
        let next_tick = tick_node.next_tick;
        if prev_tick != NONE_TICK {
            let mut prev_node = get_tick_node(state, market_id, side.as_u8(), prev_tick)?;
            prev_node.next_tick = next_tick;
            set_tick_node(state, market_id, side.as_u8(), prev_tick, &prev_node)?;
        }
        if next_tick != NONE_TICK {
            let mut next_node = get_tick_node(state, market_id, side.as_u8(), next_tick)?;
            next_node.prev_tick = prev_tick;
            set_tick_node(state, market_id, side.as_u8(), next_tick, &next_node)?;
        }
        let mut best = get_market_best(state, market_id)?;
        match side {
            Side::Buy => {
                if best.best_bid == tick {
                    best.best_bid = next_tick;
                }
            }
            Side::Sell => {
                if best.best_ask == tick {
                    best.best_ask = next_tick;
                }
            }
        }
        set_tick_node(
            state,
            market_id,
            side.as_u8(),
            tick,
            &TickNode {
                prev_tick: NONE_TICK,
                next_tick: NONE_TICK,
                head_order_id: NONE_ORDER_ID,
                tail_order_id: NONE_ORDER_ID,
            },
        )?;
        set_market_best(state, market_id, &best)?;
    } else {
        set_tick_node(state, market_id, side.as_u8(), tick, &tick_node)?;
    }
    Ok(())
}
