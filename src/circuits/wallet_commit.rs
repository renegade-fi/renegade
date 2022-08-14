use std::marker::PhantomData;

use ark_ff::PrimeField;
use ark_r1cs_std::{fields::fp::FpVar, prelude::{AllocVar, Boolean}, uint64::UInt64, uint8::UInt8, ToBitsGadget};
use ark_relations::r1cs::SynthesisError;
use ark_sponge::poseidon::PoseidonParameters;

use crate::state::Wallet;

use super::{types::{OrderVar, WalletVar}, wallet_match::SystemField, constants::POSEIDON_MDS_MATRIX_T_3};
