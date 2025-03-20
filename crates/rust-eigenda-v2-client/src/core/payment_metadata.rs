use ethereum_types::Address;
use num_bigint::BigInt;

#[derive(Debug, PartialEq)]
pub struct PaymentMetadata {
    account_id: Address,
    timestamp: i64,
    cumulative_payment: BigInt,
}