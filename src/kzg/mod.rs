use crate::{blob, bls};

mod poly;
mod setup;

#[cfg(test)]
mod spec;

pub type Proof = bls::P1;
pub type Commitment = bls::P1;

pub enum Error {
    Blob(blob::Error),
    Bls(bls::Error),
}

impl From<blob::Error> for Error {
    fn from(value: blob::Error) -> Self {
        Self::Blob(value)
    }
}

impl From<bls::Error> for Error {
    fn from(value: bls::Error) -> Self {
        Self::Bls(value)
    }
}

pub(crate) use poly::Polynomial;

pub use setup::Setup;
