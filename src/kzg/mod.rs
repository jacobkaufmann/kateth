use crate::bls;

mod poly;
mod setup;

pub type Proof = bls::P1;
pub type Commitment = bls::P1;

pub enum Error {
    Bls(bls::Error),
}

pub(crate) use poly::Polynomial;

pub use setup::Setup;
