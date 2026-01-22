use clob_core::math::{mul_div_down, mul_div_up};
use clob_core::types::U256;

#[test]
fn mul_div_down_basic() {
    let a = U256::from(10u64);
    let b = U256::from(20u64);
    let d = U256::from(6u64);
    let out = mul_div_down(a, b, d).expect("mul_div_down");
    assert_eq!(out, U256::from(33u64));
}

#[test]
fn mul_div_up_basic() {
    let a = U256::from(10u64);
    let b = U256::from(20u64);
    let d = U256::from(6u64);
    let out = mul_div_up(a, b, d).expect("mul_div_up");
    assert_eq!(out, U256::from(34u64));
}
