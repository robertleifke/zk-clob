use crate::errors::CoreError;
use crate::types::{U256, U512};

fn to_u512(value: U256) -> U512 {
    let mut buf = [0u8; 64];
    let mut tmp = [0u8; 32];
    value.to_big_endian(&mut tmp);
    buf[32..].copy_from_slice(&tmp);
    U512::from_big_endian(&buf)
}

fn to_u256(value: U512) -> Result<U256, CoreError> {
    let mut buf = [0u8; 64];
    value.to_big_endian(&mut buf);
    if buf[..32].iter().any(|b| *b != 0) {
        return Err(CoreError::Math("mul_div overflow"));
    }
    Ok(U256::from_big_endian(&buf[32..]))
}

pub fn mul_div_down(a: U256, b: U256, denom: U256) -> Result<U256, CoreError> {
    if denom.is_zero() {
        return Err(CoreError::Math("division by zero"));
    }
    let prod = to_u512(a) * to_u512(b);
    let q = prod / to_u512(denom);
    to_u256(q)
}

pub fn mul_div_up(a: U256, b: U256, denom: U256) -> Result<U256, CoreError> {
    if denom.is_zero() {
        return Err(CoreError::Math("division by zero"));
    }
    let prod = to_u512(a) * to_u512(b);
    let denom_512 = to_u512(denom);
    let numerator = if prod.is_zero() {
        prod
    } else {
        prod + denom_512 - U512::from(1u8)
    };
    let q = numerator / denom_512;
    to_u256(q)
}
