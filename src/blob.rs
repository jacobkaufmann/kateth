use crate::{
    bls::{FiniteFieldError, Fr, Scalar, P1},
    kzg::{Commitment, Polynomial, Proof, Setup},
    math::BitReversalPermutation,
};

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

    pub(crate) fn commitment<const G1: usize, const G2: usize>(
        &self,
        setup: impl AsRef<Setup<G1, G2>>,
    ) -> Commitment {
        assert_eq!(G1, N);

        let g1_lagrange = BitReversalPermutation::new(setup.as_ref().g1_lagrange.as_slice());
        let lincomb = P1::lincomb(
            g1_lagrange
                .iter()
                .zip(self.elements.iter().map(Scalar::from)),
        );

        Commitment::from(lincomb)
    }

    pub(crate) fn proof<const G1: usize, const G2: usize>(
        &self,
        commitment: &Commitment,
        setup: impl AsRef<Setup<G1, G2>>,
    ) -> Proof {
        let poly = Polynomial(self.elements.clone());
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
        let domain = b"FSBLOBVERIFY_V1_";
        let degree = (N as u128).to_be_bytes();

        let comm = commitment.0.serialize();

        let mut data = Vec::with_capacity(8 + 16 + Commitment::BYTES + Self::BYTES);
        data.extend_from_slice(domain);
        data.extend_from_slice(&degree);
        for element in self.elements.iter() {
            let bytes = Scalar::from(element).to_be_bytes();
            data.extend_from_slice(&bytes);
        }
        data.extend_from_slice(&comm);

        Fr::hash_to(data)
    }
}
