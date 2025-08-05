//! The proof manager manages job queues for generating proofs when updates
//! happen to the state. It provides an abstracted messaging interface for other
//! workers to submit proof requests to.

use std::{sync::Arc, thread::JoinHandle};

use circuit_types::traits::{SingleProverCircuit, setup_preprocessed_keys};
use circuits::{
    singleprover_prove_with_hint,
    zk_circuits::{
        valid_commitments::{
            SizedValidCommitments, SizedValidCommitmentsWitness, ValidCommitmentsStatement,
        },
        valid_fee_redemption::{
            SizedValidFeeRedemption, SizedValidFeeRedemptionStatement,
            SizedValidFeeRedemptionWitness,
        },
        valid_malleable_match_settle_atomic::{
            SizedValidMalleableMatchSettleAtomic, SizedValidMalleableMatchSettleAtomicStatement,
            SizedValidMalleableMatchSettleAtomicWitness,
        },
        valid_match_settle::{
            SizedValidMatchSettle, SizedValidMatchSettleStatement, SizedValidMatchSettleWitness,
        },
        valid_match_settle_atomic::{
            SizedValidMatchSettleAtomic, SizedValidMatchSettleAtomicStatement,
            SizedValidMatchSettleAtomicWitness,
        },
        valid_offline_fee_settlement::{
            SizedValidOfflineFeeSettlement, SizedValidOfflineFeeSettlementStatement,
            SizedValidOfflineFeeSettlementWitness,
        },
        valid_reblind::{SizedValidReblind, SizedValidReblindWitness, ValidReblindStatement},
        valid_relayer_fee_settlement::{
            SizedValidRelayerFeeSettlement, SizedValidRelayerFeeSettlementStatement,
            SizedValidRelayerFeeSettlementWitness,
        },
        valid_wallet_create::{
            SizedValidWalletCreate, SizedValidWalletCreateStatement, SizedValidWalletCreateWitness,
        },
        valid_wallet_update::{
            SizedValidWalletUpdate, SizedValidWalletUpdateStatement, SizedValidWalletUpdateWitness,
        },
    },
};
use common::{
    default_wrapper::DefaultOption,
    types::{CancelChannel, proof_bundles::ProofBundle},
};
use constants::in_bootstrap_mode;
use job_types::proof_manager::{ProofJob, ProofManagerJob, ProofManagerReceiver};
use rayon::ThreadPool;
use tracing::{error, info, info_span, instrument};
use util::{channels::TracedMessage, concurrency::runtime::sleep_forever_blocking, err_str};

use crate::worker::ProofManagerConfig;

use super::error::ProofManagerError;

// -------------
// | Constants |
// -------------

// --------------------
// | Proof Generation |
// --------------------

impl ProofManager {}
