use crate::{
    bls::{FiniteFieldError, Fr, Scalar, P1},
    kzg::{Commitment, Setup, Proof, Polynomial},
    math::BitReversalPermutation,
};

use alloy_primitives::{FixedBytes, U256};
use sha2::{Digest, Sha256};

pub enum Error {
    InvalidFieldElement,
    InvalidLen,
}

impl From<FiniteFieldError> for Error {
    fn from(_err: FiniteFieldError) -> Self {
        Self::InvalidFieldElement
    }
}

// TODO: a blob and a polynomial are essentially the same as written. if that holds, then there
// ought to be a zero-cost conversion between blob and polynomial.
pub struct Blob<const N: usize> {
    pub(crate) elements: Box<[Fr; N]>,
}

impl<const N: usize> Blob<N> {
    pub const BYTES: usize = Fr::BYTES * N;

    pub fn from_slice(bytes: impl AsRef<[u8]>) -> Result<Self, Error> {
        if bytes.as_ref().len() != Self::BYTES {
            return Err(Error::InvalidLen);
        }

        let mut elements = Box::new([Fr::default(); N]);
        for (i, chunk) in bytes.as_ref().chunks_exact(Fr::BYTES).enumerate() {
            elements[i] = Fr::from_be_slice(chunk)?;
        }

        Ok(Self { elements })
    }

    pub fn commitment<const G1: usize, const G2: usize>(
        &self,
        setup: impl AsRef<Setup<G1, G2>>,
    ) -> Commitment {
        assert_eq!(G1, N);

        // TODO: optimize w/ pippenger
        let mut lincomb = P1::INF;
        let g1_lagrange = BitReversalPermutation::new(setup.as_ref().g1_lagrange.as_slice());
        for i in 0..N {
            lincomb = lincomb + (g1_lagrange[i] * Scalar::from(self.elements[i]));
        }

        Commitment::from(lincomb)
    }

    pub fn proof<const G1: usize, const G2: usize>(&self, commitment: Commitment, setup: impl AsRef<Setup<G1, G2>>) -> Proof {
        let poly = Polynomial(self.elements.clone());
        let challenge = self.challenge(commitment);
        let (_, proof) = poly.prove(challenge, setup);
        proof
    }

    fn challenge(&self, commitment: Commitment) -> Fr {
        let domain = b"FSBLOBVERIFY_V1_";
        let degree = (N as u128).to_be_bytes();

        let comm = commitment.as_ref().compress();

        let mut data = Vec::with_capacity(8 + 16 + Commitment::BYTES + Self::BYTES);
        data.extend_from_slice(domain);
        data.extend_from_slice(&degree);
        for element in self.elements.iter() {
            let bytes = Scalar::from(element).to_be_bytes();
            data.extend_from_slice(&bytes);
        }
        data.extend_from_slice(&comm);

        hash_to_fr(data)
    }
}

fn hash_to_fr(data: impl AsRef<[u8]>) -> Fr {
    // TODO: `blst_sha256`
    let mut hasher = Sha256::new();
    hasher.update(data);
    let hash: [u8; Scalar::BYTES] = hasher.finalize().into();

    let modulus = U256::from_be_bytes(Fr::MODULUS.to_be_bytes());
    let hash = U256::from_be_bytes(hash);
    let hash = hash.reduce_mod(modulus);

    let hash: [u8; Fr::BYTES] = hash.to_be_bytes();
    let hash = FixedBytes::from(hash);

    Fr::from_be_bytes(hash).unwrap()
}