use p256k1::{point::Error as PointError, scalar::Scalar};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum DkgError {
    #[error("missing shares from {0:?}")]
    MissingShares(Vec<usize>),
    #[error("bad IDs {0:?}")]
    BadIds(Vec<usize>),
    #[error("not enough shares {0:?}")]
    NotEnoughShares(Vec<usize>),
    #[error("bad shares {0:?}")]
    BadShares(Vec<usize>),
    #[error("point error {0:?}")]
    Point(PointError),
}

impl From<PointError> for DkgError {
    fn from(e: PointError) -> Self {
        DkgError::Point(e)
    }
}

#[derive(Error, Debug)]
pub enum AggregatorError {
    #[error("bad poly commitment length (expected {0} got {1}")]
    BadPolyCommitmentLen(usize, usize),
    #[error("bad poly commitments {0:?}")]
    BadPolyCommitments(Vec<Scalar>),
    #[error("bad nonce length (expected {0} got {1}")]
    BadNonceLen(usize, usize),
    #[error("bad party sigs from {0:?}")]
    BadPartySigs(Vec<usize>),
    #[error("bad group sig")]
    BadGroupSig,
}
