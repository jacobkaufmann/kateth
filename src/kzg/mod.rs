use crate::bls;

mod commitment;
mod poly;
mod proof;
mod setup;

pub enum Error {
    Bls(bls::Error),
}

pub(crate) use poly::Polynomial;

pub use commitment::Commitment;
pub use proof::Proof;
pub use setup::Setup;
