use std::{
    fs::File,
    io::{self, BufReader},
    path::Path,
};

use crate::{
    bls::{self, Fr, Scalar, P1, P2},
    math::{self, BitReversalPermutation},
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
    pub(crate) g1_lagrange: Box<[P1; G1]>,
    #[allow(dead_code)]
    pub(crate) g2_monomial: Box<[P2; G2]>,
}

impl<const G1: usize, const G2: usize> Setup<G1, G2> {
    pub fn load(path: impl AsRef<Path>) -> Result<Self, LoadSetupError> {
        let file = File::open(path).map_err(LoadSetupError::Io)?;
        let reader = BufReader::new(file);
        let setup: SetupUnchecked =
            serde_json::from_reader(reader).map_err(LoadSetupError::Serde)?;

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
            let point = FixedBytes::<48>::from_slice(point);
            let point =
                P1::deserialize(point).map_err(|err| LoadSetupError::Bls(bls::Error::from(err)))?;
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
            let point = FixedBytes::<96>::from_slice(point);
            let point =
                P2::deserialize(point).map_err(|err| LoadSetupError::Bls(bls::Error::from(err)))?;
            g2_monomial[i] = point;
        }

        Ok(Setup {
            g1_lagrange,
            g2_monomial,
        })
    }
}

pub struct Polynomial<const N: usize>(pub(crate) Box<[Fr; N]>);

impl<const N: usize> Polynomial<N> {
    /// evaluates the polynomial at `point`.
    pub fn evaluate(&self, point: Fr) -> Fr {
        let roots = math::roots_of_unity::<N>();
        let roots = BitReversalPermutation::new(roots);

        // if `point` is a root of a unity, then we have the evaluation available
        for i in 0..N {
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
        let roots = BitReversalPermutation::new(roots);

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

        let g1_lagrange = BitReversalPermutation::new(setup.as_ref().g1_lagrange.as_slice());
        let lincomb = P1::lincomb(g1_lagrange.iter().zip(quotient_poly));

        (eval, Proof(lincomb))
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Commitment(pub(crate) P1);

impl Commitment {
    pub const BYTES: usize = P1::BYTES;

    pub fn deserialize<T: AsRef<[u8; Self::BYTES]>>(bytes: T) -> Result<Self, Error> {
        P1::deserialize(bytes)
            .map(Self)
            .map_err(|err| Error::Bls(bls::Error::from(err)))
    }
}

impl From<P1> for Commitment {
    fn from(point: P1) -> Self {
        Self(point)
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Proof(pub(crate) P1);

impl Proof {
    pub const BYTES: usize = P1::BYTES;

    pub fn deserialize<T: AsRef<[u8; Self::BYTES]>>(bytes: T) -> Result<Self, Error> {
        P1::deserialize(bytes)
            .map(Self)
            .map_err(|err| Error::Bls(bls::Error::from(err)))
    }
}

impl From<P1> for Proof {
    fn from(point: P1) -> Self {
        Self(point)
    }
}

pub fn verify<const G1: usize, const G2: usize>(
    proof: Proof,
    commitment: Commitment,
    point: Fr,
    eval: Fr,
    setup: impl AsRef<Setup<G1, G2>>,
) -> bool {
    let pairing1 = (
        proof.0,
        setup.as_ref().g2_monomial[1] + (P2::neg_generator() * Scalar::from(point)),
    );
    let pairing2 = (
        commitment.0 + (P1::neg_generator() * Scalar::from(eval)),
        P2::generator(),
    );
    bls::verify_pairings(pairing1, pairing2)
}

pub fn verify_batch<const G1: usize, const G2: usize>(
    proofs: impl AsRef<[Proof]>,
    commitments: impl AsRef<[Commitment]>,
    points: impl AsRef<[Fr]>,
    evals: impl AsRef<[Fr]>,
    setup: impl AsRef<Setup<G1, G2>>,
) -> bool {
    assert_eq!(proofs.as_ref().len(), commitments.as_ref().len());
    assert_eq!(commitments.as_ref().len(), points.as_ref().len());
    assert_eq!(points.as_ref().len(), evals.as_ref().len());

    let domain = b"RCKZGBATCH___V1_";
    let degree = (G1 as u128).to_be_bytes();
    let len = (proofs.as_ref().len() as u128).to_be_bytes();

    let mut data = Vec::with_capacity(16 + 16 + 16);
    data.extend_from_slice(domain.as_slice());
    data.extend_from_slice(&degree);
    data.extend_from_slice(&len);

    let r = Fr::hash_to(data);
    let mut rpowers = Vec::with_capacity(proofs.as_ref().len());
    for i in 0..proofs.as_ref().len() {
        rpowers.push(r.pow(Fr::from(i as u64)));
    }

    let proof_lincomb = P1::lincomb(
        proofs
            .as_ref()
            .iter()
            .map(|p| p.0)
            .zip(rpowers.iter().map(Scalar::from)),
    );
    let proof_z_lincomb = P1::lincomb(
        proofs.as_ref().iter().map(|p| p.0).zip(
            points
                .as_ref()
                .iter()
                .zip(rpowers.iter())
                .map(|(point, pow)| Scalar::from(*point * *pow)),
        ),
    );

    let comm_minus_eval = commitments
        .as_ref()
        .iter()
        .zip(evals.as_ref().iter())
        .map(|(comm, eval)| comm.0 + (P1::neg_generator() * Scalar::from(eval)));
    let comm_minus_eval_lincomb =
        P1::lincomb(comm_minus_eval.zip(rpowers.iter().map(Scalar::from)));

    bls::verify_pairings(
        (proof_lincomb, setup.as_ref().g2_monomial[1]),
        (comm_minus_eval_lincomb + proof_z_lincomb, P2::generator()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::blob::Blob;

    use std::{
        fs::{self, File},
        io::BufReader,
        path::PathBuf,
        sync::Arc,
    };

    use crate::bls::P1;

    use alloy_primitives::{Bytes, FixedBytes};

    const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
    const SETUP_G2_LEN: usize = 65;

    #[derive(serde::Deserialize, serde::Serialize)]
    struct ComputeKzgProofInputUnchecked {
        pub blob: Bytes,
        pub z: Bytes,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct ComputeKzgProofUnchecked {
        input: ComputeKzgProofInputUnchecked,
        output: Option<(FixedBytes<{ Proof::BYTES }>, FixedBytes<{ Fr::BYTES }>)>,
    }

    struct ComputeKzgProofInput {
        pub blob: Blob<FIELD_ELEMENTS_PER_BLOB>,
        pub z: Fr,
    }

    impl ComputeKzgProofInput {
        pub fn from_unchecked(unchecked: ComputeKzgProofInputUnchecked) -> Result<Self, ()> {
            let blob = Blob::from_slice(unchecked.blob).map_err(|_| ())?;
            match Fr::from_be_slice(unchecked.z) {
                Ok(z) => Ok(ComputeKzgProofInput { blob, z }),
                Err(_) => Err(()),
            }
        }
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct BlobToCommitmentInputUnchecked {
        pub blob: Bytes,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct BlobToCommitmentUnchecked {
        input: BlobToCommitmentInputUnchecked,
        output: Option<FixedBytes<{ Commitment::BYTES }>>,
    }

    struct BlobToCommitmentInput {
        pub blob: Blob<FIELD_ELEMENTS_PER_BLOB>,
    }

    impl BlobToCommitmentInput {
        pub fn from_unchecked(unchecked: BlobToCommitmentInputUnchecked) -> Result<Self, ()> {
            let blob = Blob::from_slice(unchecked.blob).map_err(|_| ())?;
            Ok(Self { blob })
        }
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct ComputeBlobKzgProofInputUnchecked {
        blob: Bytes,
        commitment: Bytes,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct ComputeBlobKzgProofUnchecked {
        input: ComputeBlobKzgProofInputUnchecked,
        output: Option<FixedBytes<{ Proof::BYTES }>>,
    }

    struct ComputeBlobKzgProofInput {
        blob: Blob<FIELD_ELEMENTS_PER_BLOB>,
        commitment: Commitment,
    }

    impl ComputeBlobKzgProofInput {
        pub fn from_unchecked(unchecked: ComputeBlobKzgProofInputUnchecked) -> Result<Self, ()> {
            let blob = Blob::from_slice(unchecked.blob).map_err(|_| ())?;
            if unchecked.commitment.len() != Commitment::BYTES {
                return Err(());
            }
            let commitment = FixedBytes::<{ Commitment::BYTES }>::from_slice(&unchecked.commitment);
            let commitment = Commitment::deserialize(commitment).map_err(|_| ())?;
            Ok(Self { blob, commitment })
        }
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct VerifyKzgProofUnchecked {
        input: VerifyKzgProofInputUnchecked,
        output: Option<bool>,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct VerifyKzgProofInputUnchecked {
        pub commitment: Bytes,
        pub z: Bytes,
        pub y: Bytes,
        pub proof: Bytes,
    }

    struct VerifyKzgProofInput {
        pub commitment: Commitment,
        pub z: Fr,
        pub y: Fr,
        pub proof: Proof,
    }

    impl VerifyKzgProofInput {
        pub fn from_unchecked(unchecked: VerifyKzgProofInputUnchecked) -> Result<Self, ()> {
            if unchecked.commitment.len() != Commitment::BYTES {
                return Err(());
            }
            let commitment = FixedBytes::<{ Commitment::BYTES }>::from_slice(&unchecked.commitment);
            let commitment = Commitment::deserialize(&commitment).map_err(|_| ())?;

            let z = Fr::from_be_slice(unchecked.z).map_err(|_| ())?;
            let y = Fr::from_be_slice(unchecked.y).map_err(|_| ())?;

            if unchecked.proof.len() != Proof::BYTES {
                return Err(());
            }
            let proof = FixedBytes::<{ Proof::BYTES }>::from_slice(&unchecked.proof);
            let proof = Proof::deserialize(&proof).map_err(|_| ())?;

            Ok(Self {
                commitment,
                z,
                y,
                proof,
            })
        }
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct VerifyBlobKzgProofUnchecked {
        input: VerifyBlobKzgProofInputUnchecked,
        output: Option<bool>,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct VerifyBlobKzgProofInputUnchecked {
        pub blob: Bytes,
        pub commitment: Bytes,
        pub proof: Bytes,
    }

    struct VerifyBlobKzgProofInput {
        pub blob: Blob<FIELD_ELEMENTS_PER_BLOB>,
        pub commitment: Commitment,
        pub proof: Proof,
    }

    impl VerifyBlobKzgProofInput {
        pub fn from_unchecked(unchecked: VerifyBlobKzgProofInputUnchecked) -> Result<Self, ()> {
            let blob = Blob::from_slice(unchecked.blob).map_err(|_| ())?;
            if unchecked.commitment.len() != Commitment::BYTES {
                return Err(());
            }
            let commitment = FixedBytes::<{ Commitment::BYTES }>::from_slice(&unchecked.commitment);
            let commitment = Commitment::deserialize(commitment).map_err(|_| ())?;
            if unchecked.proof.len() != Proof::BYTES {
                return Err(());
            }
            let proof = FixedBytes::<{ Proof::BYTES }>::from_slice(&unchecked.proof);
            let proof = Proof::deserialize(proof).map_err(|_| ())?;
            Ok(Self {
                blob,
                commitment,
                proof,
            })
        }
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct VerifyBlobKzgProofBatchInputUnchecked {
        blobs: Vec<Bytes>,
        commitments: Vec<Bytes>,
        proofs: Vec<Bytes>,
    }

    #[derive(serde::Deserialize, serde::Serialize)]
    struct VerifyBlobKzgProofBatchUnchecked {
        input: VerifyBlobKzgProofBatchInputUnchecked,
        output: Option<bool>,
    }

    struct VerifyBlobKzgProofBatchInput {
        blobs: Vec<Blob<FIELD_ELEMENTS_PER_BLOB>>,
        commitments: Vec<Commitment>,
        proofs: Vec<Proof>,
    }

    impl VerifyBlobKzgProofBatchInput {
        pub fn from_unchecked(
            unchecked: VerifyBlobKzgProofBatchInputUnchecked,
        ) -> Result<Self, ()> {
            if unchecked.blobs.len() != unchecked.commitments.len()
                || unchecked.blobs.len() != unchecked.proofs.len()
            {
                return Err(());
            }

            let mut blobs = vec![];
            for blob in unchecked.blobs {
                let blob = Blob::from_slice(blob).map_err(|_| ())?;
                blobs.push(blob);
            }

            let mut commitments = vec![];
            for commitment in unchecked.commitments {
                if commitment.len() != Commitment::BYTES {
                    return Err(());
                }
                let commitment = FixedBytes::<{ Commitment::BYTES }>::from_slice(&commitment);
                let commitment = Commitment::deserialize(commitment).map_err(|_| ())?;
                commitments.push(commitment);
            }

            let mut proofs = vec![];
            for proof in unchecked.proofs {
                if proof.len() != Proof::BYTES {
                    return Err(());
                }
                let proof = FixedBytes::<{ Proof::BYTES }>::from_slice(&proof);
                let proof = Proof::deserialize(proof).map_err(|_| ())?;
                proofs.push(proof);
            }

            Ok(Self {
                blobs,
                commitments,
                proofs,
            })
        }
    }

    fn setup() -> Setup<FIELD_ELEMENTS_PER_BLOB, SETUP_G2_LEN> {
        let path = format!("{}/trusted_setup_4096.json", env!("CARGO_MANIFEST_DIR"));
        let path = PathBuf::from(path);
        Setup::load(path).unwrap()
    }

    fn consensus_spec_test_files(dir: impl AsRef<str>) -> impl Iterator<Item = File> {
        let path = format!(
            "{}/consensus-spec-tests/tests/general/deneb/kzg/{}/kzg-mainnet",
            env!("CARGO_MANIFEST_DIR"),
            dir.as_ref(),
        );
        let path = PathBuf::from(path);
        fs::read_dir(path).unwrap().map(|entry| {
            let entry = entry.unwrap();
            let path = entry.path().join("data.yaml");
            File::open(path).unwrap()
        })
    }

    #[test]
    fn compute_kzg_proof() {
        // load trusted setup
        let setup = setup();
        let setup = Arc::new(setup);

        let files = consensus_spec_test_files("compute_kzg_proof");

        for file in files {
            let reader = BufReader::new(file);
            let case: ComputeKzgProofUnchecked = serde_yaml::from_reader(reader).unwrap();

            match ComputeKzgProofInput::from_unchecked(case.input) {
                Ok(input) => {
                    let (proof, eval) = case.output.unwrap();
                    let expected_eval = Fr::from_be_bytes(eval).unwrap();
                    let expected_proof = P1::deserialize(proof).unwrap();

                    let poly = Polynomial(input.blob.elements);
                    let eval = poly.evaluate(input.z);
                    let (_eval, proof) = poly.prove(input.z, setup.clone());

                    assert_eq!(eval, expected_eval);
                    assert_eq!(proof.0, expected_proof);
                }
                Err(_) => {
                    assert!(case.output.is_none());
                }
            }
        }
    }

    #[test]
    fn compute_blob_kzg_proof() {
        let setup = setup();
        let setup = Arc::new(setup);

        let files = consensus_spec_test_files("compute_blob_kzg_proof");

        for file in files {
            let reader = BufReader::new(file);
            let case: ComputeBlobKzgProofUnchecked = serde_yaml::from_reader(reader).unwrap();

            match ComputeBlobKzgProofInput::from_unchecked(case.input) {
                Ok(input) => {
                    let proof = case.output.unwrap();
                    let proof = P1::deserialize(proof).unwrap();
                    let expected_proof = Proof::from(proof);

                    let proof = input.blob.proof(input.commitment, setup.clone());

                    assert_eq!(proof, expected_proof);
                }
                Err(_) => {
                    assert!(case.output.is_none());
                }
            }
        }
    }

    #[test]
    fn blob_to_commitment() {
        // load trusted setup
        let setup = setup();
        let setup = Arc::new(setup);

        let files = consensus_spec_test_files("blob_to_kzg_commitment");

        for file in files {
            let reader = BufReader::new(file);
            let case: BlobToCommitmentUnchecked = serde_yaml::from_reader(reader).unwrap();

            match BlobToCommitmentInput::from_unchecked(case.input) {
                Ok(input) => {
                    let comm = case.output.unwrap();
                    let comm = P1::deserialize(comm).unwrap();
                    let expected_comm = Commitment::from(comm);

                    let comm = input.blob.commitment(&setup);

                    assert_eq!(comm, expected_comm);
                }
                Err(_) => {
                    assert!(case.output.is_none());
                }
            }
        }
    }

    #[test]
    fn verify_kzg_proof() {
        // load trusted setup
        let setup = setup();
        let setup = Arc::new(setup);

        for file in consensus_spec_test_files("verify_kzg_proof") {
            let reader = BufReader::new(file);
            let case: VerifyKzgProofUnchecked = serde_yaml::from_reader(reader).unwrap();

            match VerifyKzgProofInput::from_unchecked(case.input) {
                Ok(input) => {
                    let check = verify(input.proof, input.commitment, input.z, input.y, &setup);
                    assert_eq!(check, case.output.unwrap());
                }
                Err(_) => {
                    assert!(case.output.is_none());
                }
            }
        }
    }

    #[test]
    fn verify_blob_kzg_proof() {
        // load trusted setup
        let setup = setup();
        let setup = Arc::new(setup);

        for file in consensus_spec_test_files("verify_blob_kzg_proof") {
            let reader = BufReader::new(file);
            let case: VerifyBlobKzgProofUnchecked = serde_yaml::from_reader(reader).unwrap();

            match VerifyBlobKzgProofInput::from_unchecked(case.input) {
                Ok(input) => {
                    let check = input.blob.verify(input.proof, input.commitment, &setup);
                    assert_eq!(check, case.output.unwrap());
                }
                Err(_) => {
                    assert!(case.output.is_none());
                }
            }
        }
    }

    #[test]
    fn verify_blob_kzg_proof_batch() {
        // load trusted setup
        let setup = setup();
        let setup = Arc::new(setup);

        for file in consensus_spec_test_files("verify_blob_kzg_proof_batch") {
            let reader = BufReader::new(file);
            let case: VerifyBlobKzgProofBatchUnchecked = serde_yaml::from_reader(reader).unwrap();

            match VerifyBlobKzgProofBatchInput::from_unchecked(case.input) {
                Ok(input) => {
                    let check = crate::blob::verify_batch(
                        input.blobs,
                        input.commitments,
                        input.proofs,
                        &setup,
                    );
                    assert_eq!(check, case.output.unwrap());
                }
                Err(_) => {
                    assert!(case.output.is_none());
                }
            }
        }
    }
}
