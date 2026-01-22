# NUMO SPOT CLOB V1 (SP1)

This spec defines a deterministic offchain CLOB batch transition proven inside SP1. The onchain
verifier accepts `prevRoot -> newRoot` iff the proof verifies for the exact public inputs.

All integers are big-endian fixed width. No ABI dynamic types. All hashes are Keccak-256.

## A. Hash + State Commitment

Sparse Merkle tree (depth 256, path MSB->LSB):

- `LeafHash = keccak256(0x00 || key32 || valueHash32)` for non-empty values.
- **Empty leaf hash = bytes32(0)** for absent keys (this is the only deviation needed to keep
  empty subtrees deterministic and efficient). Value hash for empty is ignored.
- `NodeHash = keccak256(0x01 || left32 || right32)`.

Keys:
```
key32 = keccak256(namespace32 || 0x1f || packedKeyMaterial)
```

Namespaces (32-byte ASCII padded):

- `NS_BAL`, `NS_NONCE`, `NS_ORDER`, `NS_ORDERNODE`, `NS_TICKNODE`, `NS_MARKETBEST`, `NS_FEEVAULT`

## B. Public Inputs

`PublicInputs` (fixed width, big-endian):

- `bytes32 prevRoot`
- `bytes32 newRoot`
- `bytes32 batchDigest`
- `bytes32 rulesHash`
- `bytes32 domainSeparator`
- `uint64  batchSeq`
- `uint64  batchTimestamp`
- `bytes32 daCommitment`
- `bytes32 tradesRoot`
- `bytes32 feesRoot`

Encoding:
```
prevRoot || newRoot || batchDigest || rulesHash || domainSeparator ||
U64(batchSeq) || U64(batchTimestamp) || daCommitment || tradesRoot || feesRoot
```

## C. Domain / Rules / Message Hashing

`domainSeparator`:
```
keccak256("NUMO_SPOT_CLOB_V1" || U64(chainId) || B32(venueId) || B32(marketId))
```

Rules serialization (fixed order):
```
B32 baseAssetId
B32 quoteAssetId
U256 priceScale (must be 1e18)
U256 tickSize
U256 lotSize
U32  takerFeeBps
U32  makerFeeBps (must be 0)
U32  maxOrdersPerBatch (default 128)
U32  maxMatchesPerOrder (default 64)
U256 maxBalance
```
`rulesHash = keccak256(serialize(Rules))`.

Message signing:
```
msgHash = keccak256(0x19 || 0x01 || domainSeparator || keccak256(serialize(Message)))
```

Message variants:

Place (type `0x01`):
```
0x01 || ADDR(trader) || U64(nonce) || B32(orderId) ||
U8(side 0=BUY 1=SELL) || U32(tif 0=GTC 1=IOC) || I32(tickIndex) || U256(qtyBase)
```

Cancel (type `0x02`):
```
0x02 || ADDR(trader) || U64(nonce) || B32(orderId)
```

Batch digest:
```
batchDigest = keccak256("BATCH_V1" || domainSeparator || U64(batchSeq) ||
                        keccak256(msgHash_0 || ... || msgHash_{n-1}))
```

Signatures are 65 bytes `(r[32], s[32], v[1])` with `v` in {27,28} or {0,1}.

## D. Matching Rules

- Limit-only, continuous, spot-only.
- Tick size and lot size enforced.
- FIFO at each tick; ticks sorted (ASK ascending, BID descending).
- Trade price = maker tick price.
- Maker fee = 0. Taker fee charged on quote with `mulDivUp`.
- All arithmetic checked, balances capped by `maxBalance`.

Locking:

- BUY: `lockQuote = mulDivUp(price, qtyBase, 1e18)` in quote.
- SELL: `lockBase = qtyBase` in base.

Fills:

```
quoteAmt = mulDivDown(price, fillQtyBase, 1e18)
fee = mulDivUp(quoteAmt, takerFeeBps, 10_000)
```

Taker BUY:
- spend locked quote = `quoteAmt + fee`
- receive available base += `fillQtyBase`

Taker SELL:
- spend locked base = `fillQtyBase`
- receive available quote += `quoteAmt - fee`

Maker balances update symmetrically; fees accrue to `FeeVault[quote]`.

TIF:

- IOC: remaining canceled and collateral released.
- GTC: remaining rests at tick; if tick inactive, insert using witness hints.

## E. Hints (Witness-Only)

For tick insertion when a new tick becomes active, the host provides `prevTickHint` and
`nextTickHint` **outside** the signed message. The guest verifies adjacency and ordering against
state, so hints are not security-sensitive.

## F. Trades / Fees Roots

Trade record:
```
B32 marketId || B32 makerOrderId || B32 takerOrderId || ADDR(maker) || ADDR(taker) ||
U8 sideTaker || I32 makerTickIndex || U256 qtyBase || U256 quoteAmt || U256 takerFeeQuote
```

`tradeLeaf = keccak256(record)`

`tradesRoot` is a binary Merkle root over trade leaves in execution order. If odd count, the last
leaf is duplicated. If no trades, root is `bytes32(0)`.

Fee totals:
```
B32 assetId || U256 totalFee
```
sorted by `assetId` asc; `feeLeaf = keccak256(record)`; root computed as above, or zero if empty.

## G. Guest Input Format

Guest input is a single byte blob:

1) `PublicInputsPartial` (all fields except `newRoot/tradesRoot/feesRoot`)
2) `chainId`, `venueId`, `marketId`
3) `Rules`
4) `U32 messageCount` + messages with signatures (Place includes tick hints)
5) `U32 proofCount` + proofs (key, value bytes, 256 siblings)

The guest parser rejects trailing bytes.

## H. Touched Keys

The guest records every key accessed (read or write) in order and emits a private
`touchedKeysDigest = keccak256(key0 || key1 || ...)` for debugging.
