use core::num;

use crate::core::{OnDemandPayment, PaymentMetadata, ReservedPayment};
use ark_ff::Zero;
use ethereum_types::Address;
use num_bigint::BigInt;

#[derive(Debug, PartialEq)]
pub struct PeriodRecord {
    index: u32,
    usage: u64,
}

#[derive(Debug, PartialEq)]
pub struct Accountant {
    // on-chain states
    account_id: Address,
    reservation: ReservedPayment,
    on_demand: OnDemandPayment,
    reservation_window: u64,
    price_per_symbol: u64,
    min_num_symbols: u64,

    // local accounting
    period_records: Vec<PeriodRecord>,
    cumulative_payment: BigInt,

    num_bins: u32,
}

impl Accountant {
    /// TODO: add docs
    fn account_blob(
        &mut self,
        timestamp: i64,
        num_symbols: u64,
        quorums: &[u8],
    ) -> Result<PaymentMetadata, String> {
        let cumulative_payment = self.blob_payment_info(num_symbols, quorums, timestamp)?;

        let payment_metadata = PaymentMetadata {
            account_id: self.account_id.clone(),
            timestamp,
            cumulative_payment,
        };

        Ok(payment_metadata)
    }

    // Calculates and records payment information. The accountant
    // will attempt to use the active reservation first and check for quorum settings,
    // then on-demand if the reservation is not available. It takes in a timestamp at
    // the current UNIX time in nanoseconds, and returns a cumulative payment for on-
    // demand payments in units of wei. Both timestamp and cumulative payment are used
    // to create the payment header and signature, with non-zero cumulative payment
    // indicating on-demand payment.
    // These generated values are used to create the payment header and signature, as specified in
    // api/proto/common/v2/common_v2.proto
    fn blob_payment_info(
        &mut self,
        num_symbols: u64,
        quorums: &[u8],
        timestamp: i64,
    ) -> Result<BigInt, String> {
        let current_reservation_period =
            get_reservation_info_by_nanosecond(timestamp, self.reservation_window);
        let symbol_usage = self.symbols_charged(num_symbols);

        let mut relative_period_record = self.relative_period_record(current_reservation_period);

        // first attempt to use the active reservation
        let bin_limit = self.reservation.symbols_per_second * self.reservation_window;
        if relative_period_record.usage <= bin_limit {
            if let Err(_) = quorum_check(quorums, &self.reservation.quorum_numbers) {
                return Ok(BigInt::zero());
            }
            return Ok(BigInt::zero());
        }

        let mut overflow_period_record =
            self.relative_period_record(current_reservation_period + 2);

        // allow one overflow when the overflow bin is empty, the current usage and new length are both less than the limit
        if overflow_period_record.usage.is_zero()
            && relative_period_record.usage - symbol_usage < bin_limit
            && symbol_usage <= bin_limit
        {
            overflow_period_record.usage += relative_period_record.usage - bin_limit;
            if let Err(_) = quorum_check(quorums, &self.reservation.quorum_numbers) {
                return Ok(BigInt::zero());
            }
            return Ok(BigInt::zero());
        }

        // reservation not available, rollback reservation records, attempt on-demand
        //todo: rollback on-demand if disperser respond with some type of rejection?
        relative_period_record.usage -= symbol_usage;
        let increment_required = self.payment_charged(num_symbols);
        self.cumulative_payment += increment_required;

        let required_quorums = vec![0, 1];
        if self.cumulative_payment <= self.on_demand.cumulative_payment {
            if let Err(_) = quorum_check(quorums, &required_quorums) {
                return Ok(BigInt::zero())
            }
            return Ok(self.cumulative_payment.clone())
        }

        Err("neither reservation nor on-demand payment is available".to_string())
    }

    /// Returns the chargeable price for a given data length
    fn payment_charged(&self, num_symbols: u64) -> u64 {
        self.symbols_charged(num_symbols) * self.price_per_symbol
    }

    // Returns the number of symbols charged for a given data length
    // being at least `min_num_symbols` or the nearest rounded-up multiple of `min_num_symbols`.
    fn symbols_charged(&self, num_symbols: u64) -> u64 {
        if num_symbols <= self.min_num_symbols {
            return self.min_num_symbols;
        }
        // Round up to the nearest multiple of `min_num_symbols`
        return round_up_divide(num_symbols, self.min_num_symbols) * self.min_num_symbols;
    }

    fn relative_period_record(&self, reservation_period: u64) -> PeriodRecord {
        todo!()
    }
}

fn round_up_divide(num: u64, divisor: u64) -> u64 {
    (num + divisor - 1) / divisor
}

fn get_reservation_info_by_nanosecond(timestamp: i64, reservation_window: u64) -> u64 {
    todo!()
}

fn quorum_check(quorum_numbers: &[u8], reservation_quorum_numbers: &[u8]) -> Result<(), String> {
    todo!()
}
