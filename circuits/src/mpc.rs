//! Groups logic around MPC structure
use std::{
    cell::{Ref, RefCell},
    net::SocketAddr,
    rc::Rc,
};

use curve25519_dalek::scalar::Scalar;
use mpc_ristretto::{
    beaver::SharedValueSource,
    fabric::AuthenticatedMpcFabric,
    network::{MpcNetwork, QuicTwoPartyNet},
    BeaverSource,
};

use crate::errors::MpcError;

/**
 * Types
 */
