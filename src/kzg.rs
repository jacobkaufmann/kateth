use std::{
    fs::File,
    io::{self, BufReader},
    path::Path,
};

use crate::{
    bls::{self, Fr, Scalar, P1, P2},
    math,
};

use alloy_primitives::{hex, Bytes, FixedBytes};

pub enum Error {
    Bls(bls::Error),
}

#[derive(Debug)]
pub enum LoadSetupError {
    Bls(bls::Error),
    Io(io::Error),
    Hex(hex::FromHexError),
    Serde(serde_json::Error),
    InvalidLenG1Lagrange,
    InvalidLenG2Monomial,
}

#[derive(serde::Deserialize, serde::Serialize)]
struct SetupUnchecked {
    g1_lagrange: Vec<Bytes>,
    g2_monomial: Vec<Bytes>,
}

#[derive(Clone, Debug)]
pub struct Setup<const G1: usize, const G2: usize> {
    g1_lagrange: Box<[P1; G1]>,
    #[allow(dead_code)]
    g2_monomial: Box<[P2; G2]>,
}

impl<const G1: usize, const G2: usize> Setup<G1, G2> {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, LoadSetupError> {
        let file = File::open(path).map_err(|err| LoadSetupError::Io(err))?;
        let reader = BufReader::new(file);
        let setup: SetupUnchecked =
            serde_json::from_reader(reader).map_err(|err| LoadSetupError::Serde(err))?;

        if setup.g1_lagrange.len() != G1 {
            return Err(LoadSetupError::InvalidLenG1Lagrange);
        }
        if setup.g2_monomial.len() != G2 {
            return Err(LoadSetupError::InvalidLenG2Monomial);
        }

        let mut g1_lagrange: Box<[P1; G1]> = Box::new([P1::default(); G1]);
        for (i, point) in setup.g1_lagrange.iter().enumerate() {
            if point.len() != 48 {
                return Err(LoadSetupError::Bls(bls::Error::from(
                    bls::ECGroupError::InvalidEncoding,
                )));
            }
            // TODO: skip unnecessary allocation
            let point = FixedBytes::<48>::from_slice(&point);
            let point = P1::from_be_bytes(point)
                .map_err(|err| LoadSetupError::Bls(bls::Error::from(err)))?;
            g1_lagrange[i] = point;
        }

        let mut g2_monomial: Box<[P2; G2]> = Box::new([P2::default(); G2]);
        for (i, point) in setup.g2_monomial.iter().enumerate() {
            if point.len() != 96 {
                return Err(LoadSetupError::Bls(bls::Error::from(
                    bls::ECGroupError::InvalidEncoding,
                )));
            }
            // TODO: skip unnecessary allocation
            let point = FixedBytes::<96>::from_slice(&point);
            let point = P2::from_be_bytes(point)
                .map_err(|err| LoadSetupError::Bls(bls::Error::from(err)))?;
            g2_monomial[i] = point;
        }

        Ok(Setup {
            g1_lagrange,
            g2_monomial,
        })
    }
}

pub struct Polynomial<const N: usize>(Box<[Fr; N]>);

impl<const N: usize> Polynomial<N> {
    /// evaluates the polynomial at `point`.
    pub fn evaluate(&self, point: Fr) -> Fr {
        let roots = math::roots_of_unity::<N>();
        let roots = math::bit_reversal_permutation(&roots);

        // if `point` is a root of a unity, then we have the evaluation available
        for i in 0..roots.len() {
            if point == roots[i] {
                return self.0[i];
            }
        }

        let mut eval = Fr::ZERO;

        // barycentric evaluation summation
        for i in 0..N {
            let numer = self.0[i] * roots[i];
            let denom = point - roots[i];
            let term = numer / denom;
            eval = eval + term;
        }

        // barycentric evaluation scalar multiplication
        let term = (point.pow(Fr::from(N as u64)) - Fr::ONE) / Fr::from(N as u64);
        eval * term
    }

    /// returns a `Proof` for the evaluation of the polynomial at `point`.
    pub fn prove<const G1: usize, const G2: usize>(
        &self,
        point: Fr,
        setup: impl AsRef<Setup<G1, G2>>,
    ) -> (Fr, Proof) {
        assert_eq!(G1, N);
        let roots = math::roots_of_unity::<N>();
        let roots = math::bit_reversal_permutation(&roots);

        let eval = self.evaluate(point);

        // compute the quotient polynomial
        //
        // TODO: parallelize (e.g. rayon)
        let mut quotient_poly = Vec::with_capacity(N);
        for i in 0..N {
            let numer = self.0[i] - eval;
            let denom = roots[i] - point;
            let quotient = if denom != Fr::ZERO {
                numer / denom
            } else {
                let mut quotient = Fr::ZERO;
                for j in 0..N {
                    if j == i {
                        continue;
                    }

                    let coefficient = self.0[j] - eval;
                    let numer = coefficient * roots[j];
                    let denom = (roots[i] * roots[i]) - (roots[i] * roots[j]);
                    let term = numer / denom;
                    quotient = quotient + term;
                }
                quotient
            };
            quotient_poly.push(Scalar::from(quotient));
        }

        // TODO: with both `into_iter` there were some memory issues. we need to optimize w/ pippenger anyway.
        let mut lincomb = P1::INF;
        let g1_lagrange = math::bit_reversal_permutation(&setup.as_ref().g1_lagrange);
        for (lagrange, scalar) in g1_lagrange.iter().zip(quotient_poly.iter()) {
            lincomb = lincomb + (*lagrange * scalar.clone());
        }

        (eval, Proof(lincomb))
    }
}

pub struct Commitment(P1);

impl Commitment {
    pub const BYTES: usize = P1::BYTES;

    pub fn from_be_bytes<T: AsRef<[u8; Self::BYTES]>>(bytes: T) -> Result<Self, Error> {
        P1::from_be_bytes(bytes)
            .and_then(|p1| Ok(Self(p1)))
            .map_err(|err| Error::Bls(bls::Error::from(err)))
    }
}

pub struct Proof(P1);

impl Proof {
    pub const BYTES: usize = P1::BYTES;

    pub fn from_be_bytes<T: AsRef<[u8; Self::BYTES]>>(bytes: T) -> Result<Self, Error> {
        P1::from_be_bytes(bytes)
            .and_then(|p1| Ok(Self(p1)))
            .map_err(|err| Error::Bls(bls::Error::from(err)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        fs::{self, File},
        io::BufReader,
        path::PathBuf,
        sync::Arc,
    };

    use crate::bls::P1;

    use alloy_primitives::{Bytes, FixedBytes};

    const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
    const BYTES_PER_BLOB: usize = FIELD_ELEMENTS_PER_BLOB * Fr::BYTES;

    const SETUP_G2_LEN: usize = 65;

    #[derive(serde::Deserialize, serde::Serialize)]
    struct ComputeKzgProofInputUnchecked {
        pub blob: Bytes,
        pub z: Bytes,
    }

    struct ComputeKzgProofInput {
        pub blob: Box<[Fr; FIELD_ELEMENTS_PER_BLOB]>,
        pub z: Fr,
    }

    impl ComputeKzgProofInput {
        pub fn from_unchecked(unchecked: ComputeKzgProofInputUnchecked) -> Result<Self, ()> {
            if unchecked.blob.len() != BYTES_PER_BLOB {
                return Err(());
            }

            let mut blob = Box::new([Fr::default(); FIELD_ELEMENTS_PER_BLOB]);
            let mut i = 0;
            for felt in unchecked.blob.chunks_exact(Fr::BYTES) {
                let bytes = FixedBytes::<{ Fr::BYTES }>::from_slice(felt);
                match Fr::from_be_bytes(bytes) {
                    Some(fr) => {
                        blob[i] = fr;
                    }
                    None => return Err(()),
                }

                i += 1;
            }
            assert_eq!(i, FIELD_ELEMENTS_PER_BLOB);

            if unchecked.z.len() != Fr::BYTES {
                return Err(());
            }
            let bytes = FixedBytes::<{ Fr::BYTES }>::from_slice(&unchecked.z);
            match Fr::from_be_bytes(bytes) {
                Some(z) => Ok(ComputeKzgProofInput { blob, z }),
                None => Err(()),
            }
        }
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct ComputeKzgProofUnchecked {
        input: ComputeKzgProofInputUnchecked,
        output: Option<(FixedBytes<{ P1::BYTES }>, FixedBytes<{ Fr::BYTES }>)>,
    }

    fn setup() -> Setup<FIELD_ELEMENTS_PER_BLOB, SETUP_G2_LEN> {
        let path = format!("{}/trusted_setup_4096.json", env!("CARGO_MANIFEST_DIR"));
        let path = PathBuf::from(path);
        Setup::load(path).unwrap()
    }

    #[test]
    fn compute_kzg_proof() {
        let dir = format!(
            "{}/consensus-spec-tests/tests/general/deneb/kzg/compute_kzg_proof/kzg-mainnet",
            env!("CARGO_MANIFEST_DIR")
        );
        let dir = PathBuf::from(dir);

        // load trusted setup
        let setup = setup();
        let setup = Arc::new(setup);

        for item in fs::read_dir(dir).unwrap() {
            let item = item.unwrap();
            let path = item.path().join("data.yaml");
            let file = File::open(path.clone()).unwrap();
            let reader = BufReader::new(file);
            let case: ComputeKzgProofUnchecked = serde_yaml::from_reader(reader).unwrap();

            match ComputeKzgProofInput::from_unchecked(case.input) {
                Ok(input) => {
                    let (proof, eval) = case.output.unwrap();
                    let expected_eval = Fr::from_be_bytes(eval).unwrap();
                    let expected_proof = P1::from_be_bytes(proof).unwrap();

                    let poly = Polynomial(input.blob);
                    let eval = poly.evaluate(input.z);
                    let (_eval, proof) = poly.prove(input.z, setup.clone());

                    assert_eq!(eval, expected_eval);
                    assert_eq!(proof.0, expected_proof);
                }
                Err(_) => {
                    println!("{}", path.display());
                    assert!(case.output.is_none());
                }
            }
        }
    }
}
