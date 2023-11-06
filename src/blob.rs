use crate::{
    bls::{FiniteFieldError, Fr, Scalar, P1},
    kzg::{Commitment, Setup},
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

    // TODO: a blob and a polynomial are essentially the same as written. if that holds, then there
    // ought to be a zero-cost conversion between blob and polynomial.
    #[allow(dead_code)]

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
}
