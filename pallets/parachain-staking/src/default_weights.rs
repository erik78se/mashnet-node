// KILT Blockchain – https://botlabs.org
// Copyright (C) 2019-2021 BOTLabs GmbH

// The KILT Blockchain is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// The KILT Blockchain is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// If you feel like getting in touch with us, you can do so at info@botlabs.org

//! Autogenerated weights for parachain_staking
//!
//! THIS FILE WAS AUTO-GENERATED USING THE SUBSTRATE BENCHMARK CLI VERSION 3.0.0
//! DATE: 2021-06-17, STEPS: {{cmd.steps}}\, REPEAT: {{cmd.repeat}}\, LOW RANGE: {{cmd.lowest_range_values}}\, HIGH RANGE: {{cmd.highest_range_values}}\
//! EXECUTION: Some(Wasm), WASM-EXECUTION: Compiled, CHAIN: Some("spiritnet-dev"), DB CACHE: 128

// Executed Command:
// /home/willi/mashnet-node/target/release/kilt-parachain
// benchmark
// --chain=spiritnet-dev
// --execution=wasm
// --wasm-execution=Compiled
// --heap-pages=4096
// --extrinsic=*
// --pallet=parachain_staking
// --steps=50
// --repeat=20
// --output
// ./pallets/parachain-staking/src/default_weights.rs
// --template
// ../../.maintain/weight-template.hbs


#![cfg_attr(rustfmt, rustfmt_skip)]
#![allow(unused_parens)]
#![allow(unused_imports)]

use frame_support::{traits::Get, weights::{Weight, constants::RocksDbWeight}};
use sp_std::marker::PhantomData;

/// Weight functions needed for parachain_staking.
pub trait WeightInfo {
	fn on_initialize_no_action() -> Weight;
	fn on_initialize_round_update() -> Weight;
	fn on_initialize_new_year() -> Weight;
	fn set_inflation() -> Weight;
	fn set_max_selected_candidates(n: u32, m: u32, ) -> Weight;
	fn set_blocks_per_round() -> Weight;
	fn force_remove_candidate(m: u32, ) -> Weight;
	fn join_candidates(n: u32, m: u32, ) -> Weight;
	fn init_leave_candidates(n: u32, m: u32, ) -> Weight;
	fn cancel_leave_candidates(n: u32, m: u32, ) -> Weight;
	fn execute_leave_candidates(n: u32, m: u32, u: u32, ) -> Weight;
	fn candidate_stake_more(n: u32, m: u32, u: u32, ) -> Weight;
	fn candidate_stake_less(n: u32, m: u32, ) -> Weight;
	fn join_delegators(n: u32, m: u32, ) -> Weight;
	fn delegator_stake_more(n: u32, m: u32, u: u32, ) -> Weight;
	fn delegator_stake_less(n: u32, m: u32, ) -> Weight;
	fn revoke_delegation(n: u32, m: u32, ) -> Weight;
	fn leave_delegators(n: u32, m: u32, ) -> Weight;
	fn withdraw_unstaked(u: u32, ) -> Weight;
	fn increase_max_candidate_stake_by() -> Weight;
	fn decrease_max_candidate_stake_by(n: u32, m: u32, ) -> Weight;
}

/// Weights for parachain_staking using the Substrate node and recommended hardware.
pub struct SubstrateWeight<T>(PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
	fn on_initialize_no_action() -> Weight {
		(6_573_000_u64)
			.saturating_add(T::DbWeight::get().reads(1_u64))
	}
	fn on_initialize_round_update() -> Weight {
		(27_852_000_u64)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	fn on_initialize_new_year() -> Weight {
		(53_180_000_u64)
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().writes(3_u64))
	}
	fn set_inflation() -> Weight {
		(24_426_000_u64)
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	fn set_max_selected_candidates(n: u32, m: u32, ) -> Weight {
		(0_u64)
			// Standard Error: 23_000
			.saturating_add((24_462_000_u64).saturating_mul(n as Weight))
			// Standard Error: 65_000
			.saturating_add((15_379_000_u64).saturating_mul(m as Weight))
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().reads((1_u64).saturating_mul(n as Weight)))
			.saturating_add(T::DbWeight::get().writes(3_u64))
	}
	fn set_blocks_per_round() -> Weight {
		(28_414_000_u64)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	fn force_remove_candidate(m: u32, ) -> Weight {
		(317_877_000_u64)
			// Standard Error: 36_000
			.saturating_add((5_988_000_u64).saturating_mul(m as Weight))
	}
	fn join_candidates(n: u32, m: u32, ) -> Weight {
		(182_620_000_u64)
			// Standard Error: 86_000
			.saturating_add((3_971_000_u64).saturating_mul(n as Weight))
			// Standard Error: 314_000
			.saturating_add((8_795_000_u64).saturating_mul(m as Weight))
			.saturating_add(T::DbWeight::get().reads(17_u64))
			.saturating_add(T::DbWeight::get().writes(7_u64))
	}
	fn init_leave_candidates(n: u32, m: u32, ) -> Weight {
		(317_877_000_u64)
			// Standard Error: 13_000
			.saturating_add((1_476_000_u64).saturating_mul(n as Weight))
			// Standard Error: 36_000
			.saturating_add((5_988_000_u64).saturating_mul(m as Weight))
			.saturating_add(T::DbWeight::get().reads(21_u64))
			.saturating_add(T::DbWeight::get().writes(4_u64))
	}
	fn cancel_leave_candidates(n: u32, m: u32, ) -> Weight {
		(310_060_000_u64)
			// Standard Error: 14_000
			.saturating_add((1_537_000_u64).saturating_mul(n as Weight))
			// Standard Error: 38_000
			.saturating_add((6_002_000_u64).saturating_mul(m as Weight))
			.saturating_add(T::DbWeight::get().reads(20_u64))
			.saturating_add(T::DbWeight::get().writes(4_u64))
	}
	fn execute_leave_candidates(n: u32, m: u32, u: u32, ) -> Weight {
		(0_u64)
			// Standard Error: 21_000
			.saturating_add((2_126_000_u64).saturating_mul(n as Weight))
			// Standard Error: 57_000
			.saturating_add((34_436_000_u64).saturating_mul(m as Weight))
			// Standard Error: 215_000
			.saturating_add((1_179_000_u64).saturating_mul(u as Weight))
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().reads((2_u64).saturating_mul(m as Weight)))
			.saturating_add(T::DbWeight::get().writes(2_u64))
			.saturating_add(T::DbWeight::get().writes((2_u64).saturating_mul(m as Weight)))
	}
	fn candidate_stake_more(n: u32, m: u32, u: u32, ) -> Weight {
		(101_852_000_u64)
			// Standard Error: 84_000
			.saturating_add((3_969_000_u64).saturating_mul(n as Weight))
			// Standard Error: 312_000
			.saturating_add((8_948_000_u64).saturating_mul(m as Weight))
			// Standard Error: 1_036_000
			.saturating_add((7_018_000_u64).saturating_mul(u as Weight))
			.saturating_add(T::DbWeight::get().reads(13_u64))
			.saturating_add(T::DbWeight::get().writes(7_u64))
	}
	fn candidate_stake_less(n: u32, m: u32, ) -> Weight {
		(123_462_000_u64)
			// Standard Error: 89_000
			.saturating_add((3_927_000_u64).saturating_mul(n as Weight))
			// Standard Error: 327_000
			.saturating_add((8_759_000_u64).saturating_mul(m as Weight))
			.saturating_add(T::DbWeight::get().reads(12_u64))
			.saturating_add(T::DbWeight::get().writes(5_u64))
	}
	fn join_delegators(n: u32, m: u32, ) -> Weight {
		(183_130_000_u64)
			// Standard Error: 92_000
			.saturating_add((4_112_000_u64).saturating_mul(n as Weight))
			// Standard Error: 378_000
			.saturating_add((10_015_000_u64).saturating_mul(m as Weight))
			.saturating_add(T::DbWeight::get().reads(18_u64))
			.saturating_add(T::DbWeight::get().writes(9_u64))
	}
	fn delegator_stake_more(n: u32, m: u32, u: u32, ) -> Weight {
		(106_824_000_u64)
			// Standard Error: 83_000
			.saturating_add((3_950_000_u64).saturating_mul(n as Weight))
			// Standard Error: 349_000
			.saturating_add((9_517_000_u64).saturating_mul(m as Weight))
			// Standard Error: 1_040_000
			.saturating_add((6_805_000_u64).saturating_mul(u as Weight))
			.saturating_add(T::DbWeight::get().reads(13_u64))
			.saturating_add(T::DbWeight::get().writes(8_u64))
	}
	fn delegator_stake_less(n: u32, m: u32, ) -> Weight {
		(133_030_000_u64)
			// Standard Error: 89_000
			.saturating_add((3_915_000_u64).saturating_mul(n as Weight))
			// Standard Error: 368_000
			.saturating_add((9_328_000_u64).saturating_mul(m as Weight))
			.saturating_add(T::DbWeight::get().reads(13_u64))
			.saturating_add(T::DbWeight::get().writes(6_u64))
	}
	fn revoke_delegation(n: u32, m: u32, ) -> Weight {
		(141_273_000_u64)
			// Standard Error: 89_000
			.saturating_add((3_942_000_u64).saturating_mul(n as Weight))
			// Standard Error: 367_000
			.saturating_add((9_394_000_u64).saturating_mul(m as Weight))
			.saturating_add(T::DbWeight::get().reads(13_u64))
			.saturating_add(T::DbWeight::get().writes(6_u64))
	}
	fn leave_delegators(n: u32, m: u32, ) -> Weight {
		(138_035_000_u64)
			// Standard Error: 89_000
			.saturating_add((3_974_000_u64).saturating_mul(n as Weight))
			// Standard Error: 369_000
			.saturating_add((9_484_000_u64).saturating_mul(m as Weight))
			.saturating_add(T::DbWeight::get().reads(13_u64))
			.saturating_add(T::DbWeight::get().writes(6_u64))
	}
	fn withdraw_unstaked(u: u32, ) -> Weight {
		(59_047_000_u64)
			// Standard Error: 11_000
			.saturating_add((129_000_u64).saturating_mul(u as Weight))
			.saturating_add(T::DbWeight::get().reads(3_u64))
			.saturating_add(T::DbWeight::get().writes(3_u64))
	}
	fn increase_max_candidate_stake_by() -> Weight {
		(27_711_000_u64)
			.saturating_add(T::DbWeight::get().reads(1_u64))
			.saturating_add(T::DbWeight::get().writes(1_u64))
	}
	fn decrease_max_candidate_stake_by(n: u32, m: u32, ) -> Weight {
		(0_u64)
			// Standard Error: 62_000
			.saturating_add((61_021_000_u64).saturating_mul(n as Weight))
			// Standard Error: 228_000
			.saturating_add((37_094_000_u64).saturating_mul(m as Weight))
			.saturating_add(T::DbWeight::get().reads(4_u64))
			.saturating_add(T::DbWeight::get().reads((3_u64).saturating_mul(n as Weight)))
			.saturating_add(T::DbWeight::get().writes(4_u64))
			.saturating_add(T::DbWeight::get().writes((3_u64).saturating_mul(n as Weight)))
	}
}

// For backwards compatibility and tests
impl WeightInfo for () {
	fn on_initialize_no_action() -> Weight {
		(6_573_000_u64)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
	}
	fn on_initialize_round_update() -> Weight {
		(27_852_000_u64)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}
	fn on_initialize_new_year() -> Weight {
		(53_180_000_u64)
			.saturating_add(RocksDbWeight::get().reads(3_u64))
			.saturating_add(RocksDbWeight::get().writes(3_u64))
	}
	fn set_inflation() -> Weight {
		(24_426_000_u64)
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}
	fn set_max_selected_candidates(n: u32, m: u32, ) -> Weight {
		(0_u64)
			// Standard Error: 23_000
			.saturating_add((24_462_000_u64).saturating_mul(n as Weight))
			// Standard Error: 65_000
			.saturating_add((15_379_000_u64).saturating_mul(m as Weight))
			.saturating_add(RocksDbWeight::get().reads(3_u64))
			.saturating_add(RocksDbWeight::get().reads((1_u64).saturating_mul(n as Weight)))
			.saturating_add(RocksDbWeight::get().writes(3_u64))
	}
	fn set_blocks_per_round() -> Weight {
		(28_414_000_u64)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}
	fn force_remove_candidate(m: u32, ) -> Weight {
		(317_877_000_u64)
			// Standard Error: 36_000
			.saturating_add((5_988_000_u64).saturating_mul(m as Weight))
	}
	fn join_candidates(n: u32, m: u32, ) -> Weight {
		(182_620_000_u64)
			// Standard Error: 86_000
			.saturating_add((3_971_000_u64).saturating_mul(n as Weight))
			// Standard Error: 314_000
			.saturating_add((8_795_000_u64).saturating_mul(m as Weight))
			.saturating_add(RocksDbWeight::get().reads(17_u64))
			.saturating_add(RocksDbWeight::get().writes(7_u64))
	}
	fn init_leave_candidates(n: u32, m: u32, ) -> Weight {
		(317_877_000_u64)
			// Standard Error: 13_000
			.saturating_add((1_476_000_u64).saturating_mul(n as Weight))
			// Standard Error: 36_000
			.saturating_add((5_988_000_u64).saturating_mul(m as Weight))
			.saturating_add(RocksDbWeight::get().reads(21_u64))
			.saturating_add(RocksDbWeight::get().writes(4_u64))
	}
	fn cancel_leave_candidates(n: u32, m: u32, ) -> Weight {
		(310_060_000_u64)
			// Standard Error: 14_000
			.saturating_add((1_537_000_u64).saturating_mul(n as Weight))
			// Standard Error: 38_000
			.saturating_add((6_002_000_u64).saturating_mul(m as Weight))
			.saturating_add(RocksDbWeight::get().reads(20_u64))
			.saturating_add(RocksDbWeight::get().writes(4_u64))
	}
	fn execute_leave_candidates(n: u32, m: u32, u: u32, ) -> Weight {
		(0_u64)
			// Standard Error: 21_000
			.saturating_add((2_126_000_u64).saturating_mul(n as Weight))
			// Standard Error: 57_000
			.saturating_add((34_436_000_u64).saturating_mul(m as Weight))
			// Standard Error: 215_000
			.saturating_add((1_179_000_u64).saturating_mul(u as Weight))
			.saturating_add(RocksDbWeight::get().reads(3_u64))
			.saturating_add(RocksDbWeight::get().reads((2_u64).saturating_mul(m as Weight)))
			.saturating_add(RocksDbWeight::get().writes(2_u64))
			.saturating_add(RocksDbWeight::get().writes((2_u64).saturating_mul(m as Weight)))
	}
	fn candidate_stake_more(n: u32, m: u32, u: u32, ) -> Weight {
		(101_852_000_u64)
			// Standard Error: 84_000
			.saturating_add((3_969_000_u64).saturating_mul(n as Weight))
			// Standard Error: 312_000
			.saturating_add((8_948_000_u64).saturating_mul(m as Weight))
			// Standard Error: 1_036_000
			.saturating_add((7_018_000_u64).saturating_mul(u as Weight))
			.saturating_add(RocksDbWeight::get().reads(13_u64))
			.saturating_add(RocksDbWeight::get().writes(7_u64))
	}
	fn candidate_stake_less(n: u32, m: u32, ) -> Weight {
		(123_462_000_u64)
			// Standard Error: 89_000
			.saturating_add((3_927_000_u64).saturating_mul(n as Weight))
			// Standard Error: 327_000
			.saturating_add((8_759_000_u64).saturating_mul(m as Weight))
			.saturating_add(RocksDbWeight::get().reads(12_u64))
			.saturating_add(RocksDbWeight::get().writes(5_u64))
	}
	fn join_delegators(n: u32, m: u32, ) -> Weight {
		(183_130_000_u64)
			// Standard Error: 92_000
			.saturating_add((4_112_000_u64).saturating_mul(n as Weight))
			// Standard Error: 378_000
			.saturating_add((10_015_000_u64).saturating_mul(m as Weight))
			.saturating_add(RocksDbWeight::get().reads(18_u64))
			.saturating_add(RocksDbWeight::get().writes(9_u64))
	}
	fn delegator_stake_more(n: u32, m: u32, u: u32, ) -> Weight {
		(106_824_000_u64)
			// Standard Error: 83_000
			.saturating_add((3_950_000_u64).saturating_mul(n as Weight))
			// Standard Error: 349_000
			.saturating_add((9_517_000_u64).saturating_mul(m as Weight))
			// Standard Error: 1_040_000
			.saturating_add((6_805_000_u64).saturating_mul(u as Weight))
			.saturating_add(RocksDbWeight::get().reads(13_u64))
			.saturating_add(RocksDbWeight::get().writes(8_u64))
	}
	fn delegator_stake_less(n: u32, m: u32, ) -> Weight {
		(133_030_000_u64)
			// Standard Error: 89_000
			.saturating_add((3_915_000_u64).saturating_mul(n as Weight))
			// Standard Error: 368_000
			.saturating_add((9_328_000_u64).saturating_mul(m as Weight))
			.saturating_add(RocksDbWeight::get().reads(13_u64))
			.saturating_add(RocksDbWeight::get().writes(6_u64))
	}
	fn revoke_delegation(n: u32, m: u32, ) -> Weight {
		(141_273_000_u64)
			// Standard Error: 89_000
			.saturating_add((3_942_000_u64).saturating_mul(n as Weight))
			// Standard Error: 367_000
			.saturating_add((9_394_000_u64).saturating_mul(m as Weight))
			.saturating_add(RocksDbWeight::get().reads(13_u64))
			.saturating_add(RocksDbWeight::get().writes(6_u64))
	}
	fn leave_delegators(n: u32, m: u32, ) -> Weight {
		(138_035_000_u64)
			// Standard Error: 89_000
			.saturating_add((3_974_000_u64).saturating_mul(n as Weight))
			// Standard Error: 369_000
			.saturating_add((9_484_000_u64).saturating_mul(m as Weight))
			.saturating_add(RocksDbWeight::get().reads(13_u64))
			.saturating_add(RocksDbWeight::get().writes(6_u64))
	}
	fn withdraw_unstaked(u: u32, ) -> Weight {
		(59_047_000_u64)
			// Standard Error: 11_000
			.saturating_add((129_000_u64).saturating_mul(u as Weight))
			.saturating_add(RocksDbWeight::get().reads(3_u64))
			.saturating_add(RocksDbWeight::get().writes(3_u64))
	}
	fn increase_max_candidate_stake_by() -> Weight {
		(27_711_000_u64)
			.saturating_add(RocksDbWeight::get().reads(1_u64))
			.saturating_add(RocksDbWeight::get().writes(1_u64))
	}
	fn decrease_max_candidate_stake_by(n: u32, m: u32, ) -> Weight {
		(0_u64)
			// Standard Error: 62_000
			.saturating_add((61_021_000_u64).saturating_mul(n as Weight))
			// Standard Error: 228_000
			.saturating_add((37_094_000_u64).saturating_mul(m as Weight))
			.saturating_add(RocksDbWeight::get().reads(4_u64))
			.saturating_add(RocksDbWeight::get().reads((3_u64).saturating_mul(n as Weight)))
			.saturating_add(RocksDbWeight::get().writes(4_u64))
			.saturating_add(RocksDbWeight::get().writes((3_u64).saturating_mul(n as Weight)))
	}
}
