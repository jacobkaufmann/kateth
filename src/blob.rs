use crate::{
    bls::{FiniteFieldError, Fr, P1},
    kzg::{Commitment, Polynomial, Proof, Setup},
};

#[derive(Clone, Copy, Debug)]
pub enum Error {
    InvalidFieldElement,
    InvalidLen,
}

impl From<FiniteFieldError> for Error {
    fn from(_err: FiniteFieldError) -> Self {
        Self::InvalidFieldElement
    }
}

#[derive(Clone, Debug)]
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::BYTES);
        for element in self.elements.iter() {
            let element = element.to_be_bytes();
            bytes.extend_from_slice(&element);
        }
        bytes
    }

    pub(crate) fn commitment<const G2: usize>(&self, setup: &Setup<N, G2>) -> Commitment {
        let lincomb =
            P1::lincomb_pippenger(setup.g1_lagrange_brp.as_slice(), self.elements.as_slice());

        Commitment::from(lincomb)
    }

    pub(crate) fn proof<const G2: usize>(
        &self,
        commitment: &Commitment,
        setup: &Setup<N, G2>,
    ) -> Proof {
        let poly = Polynomial(&self.elements);
        let challenge = self.challenge(commitment);
        let (_, proof) = poly.prove(challenge, setup);
        proof
    }

    #[cfg(feature = "rand")]
    pub fn random(gen: &mut impl rand::Rng) -> Self {
        let mut elements = Box::new([Fr::default(); N]);
        for i in 0..N {
            let mut hash = vec![0; 512];
            gen.fill_bytes(&mut hash);
            elements[i] = Fr::hash_to(hash);
        }

        Self { elements }
    }

    pub(crate) fn challenge(&self, commitment: &Commitment) -> Fr {
        const DOMAIN: &[u8; 16] = b"FSBLOBVERIFY_V1_";
        let degree = (N as u128).to_be_bytes();

        let comm = commitment.serialize();

        let mut data = Vec::with_capacity(8 + 16 + Commitment::BYTES + Self::BYTES);
        data.extend_from_slice(DOMAIN);
        data.extend_from_slice(&degree);
        for element in self.elements.iter() {
            let bytes = element.to_be_bytes();
            data.extend_from_slice(&bytes);
        }
        data.extend_from_slice(&comm);

        Fr::hash_to(data)
    }
}
