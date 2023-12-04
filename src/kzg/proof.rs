use crate::bls::{Error as BlsError, P1};

use super::Error;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Proof(pub(crate) P1);

impl Proof {
    pub const BYTES: usize = P1::BYTES;

    pub fn deserialize<T: AsRef<[u8; Self::BYTES]>>(bytes: T) -> Result<Self, Error> {
        P1::deserialize(bytes)
            .map(Self)
            .map_err(|err| Error::Bls(BlsError::from(err)))
    }
}

impl From<P1> for Proof {
    fn from(point: P1) -> Self {
        Self(point)
    }
}
