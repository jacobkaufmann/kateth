use std::{
    fs::File,
    io::{self, BufReader},
    path::Path,
};

use super::{Bytes32, Bytes48, Commitment, Error, Polynomial, Proof};
use crate::{
    blob::{Blob, Error as BlobError},
    bls::{self, Decompress, ECGroupError, Error as BlsError, Fr, P1, P2},
    math,
};

use alloy_primitives::{hex, Bytes, FixedBytes};

#[derive(Debug)]
pub enum LoadSetupError {
    Bls(BlsError),
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
    pub(crate) g1_lagrange_brp: Box<[P1; G1]>,
    pub(crate) g2_monomial: Box<[P2; G2]>,
    pub(crate) roots_of_unity_brp: Box<[Fr; G1]>,
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
                return Err(LoadSetupError::Bls(BlsError::from(
                    ECGroupError::InvalidEncoding,
                )));
            }
            // TODO: skip unnecessary allocation
            let point = FixedBytes::<48>::from_slice(point);
            let point =
                P1::decompress(point).map_err(|err| LoadSetupError::Bls(BlsError::from(err)))?;
            g1_lagrange[i] = point;
        }
        let g1_lagrange_brp = math::bit_reversal_permutation_boxed_array(g1_lagrange.as_slice());

        let mut g2_monomial: Box<[P2; G2]> = Box::new([P2::default(); G2]);
        for (i, point) in setup.g2_monomial.iter().enumerate() {
            if point.len() != 96 {
                return Err(LoadSetupError::Bls(BlsError::from(
                    ECGroupError::InvalidEncoding,
                )));
            }
            // TODO: skip unnecessary allocation
            let point = FixedBytes::<96>::from_slice(point);
            let point =
                P2::decompress(point).map_err(|err| LoadSetupError::Bls(BlsError::from(err)))?;
            g2_monomial[i] = point;
        }

        let roots_of_unity: [Fr; G1] = math::roots_of_unity();
        let roots_of_unity_brp = math::bit_reversal_permutation_boxed_array(roots_of_unity);

        Ok(Setup {
            g1_lagrange_brp,
            g2_monomial,
            roots_of_unity_brp,
        })
    }

    fn verify_proof_inner(
        &self,
        proof: &Proof,
        commitment: &Commitment,
        point: &Fr,
        eval: &Fr,
    ) -> bool {
        let pairing1 = (*proof, self.g2_monomial[1] + (P2::neg_generator() * point));
        let pairing2 = (*commitment + (P1::neg_generator() * eval), P2::generator());
        bls::verify_pairings(pairing1, pairing2)
    }

    pub fn verify_proof(
        &self,
        proof: &Bytes48,
        commitment: &Bytes48,
        point: &Bytes32,
        eval: &Bytes32,
    ) -> Result<bool, Error> {
        let proof = Proof::decompress(proof).map_err(|err| Error::from(BlsError::ECGroup(err)))?;
        let commitment = Commitment::decompress(commitment)
            .map_err(|err| Error::from(BlsError::ECGroup(err)))?;
        let point =
            Fr::from_be_slice(point).map_err(|err| Error::from(BlsError::FiniteField(err)))?;
        let eval =
            Fr::from_be_slice(eval).map_err(|err| Error::from(BlsError::FiniteField(err)))?;

        let verified = self.verify_proof_inner(&proof, &commitment, &point, &eval);
        Ok(verified)
    }

    fn verify_proof_batch(
        &self,
        proofs: impl AsRef<[Proof]>,
        commitments: impl AsRef<[Commitment]>,
        points: impl AsRef<[Fr]>,
        evals: impl AsRef<[Fr]>,
    ) -> bool {
        assert_eq!(proofs.as_ref().len(), commitments.as_ref().len());
        assert_eq!(commitments.as_ref().len(), points.as_ref().len());
        assert_eq!(points.as_ref().len(), evals.as_ref().len());
        let n = proofs.as_ref().len();

        const DOMAIN: &[u8; 16] = b"RCKZGBATCH___V1_";
        let degree = (G1 as u128).to_be_bytes();
        let len = (n as u128).to_be_bytes();

        let mut data = [0; 48];
        data[..16].copy_from_slice(DOMAIN.as_slice());
        data[16..32].copy_from_slice(&degree);
        data[32..].copy_from_slice(&len);

        let r = Fr::hash_to(data);
        let mut rpowers = Vec::with_capacity(n);
        let mut points_mul_rpowers = Vec::with_capacity(n);
        let mut comms_minus_evals = Vec::with_capacity(n);
        for i in 0..proofs.as_ref().len() {
            let rpower = r.pow(&Fr::from(i as u64));
            rpowers.push(rpower);

            let point = points.as_ref()[i];
            points_mul_rpowers.push(point * rpower);

            let commitment = commitments.as_ref()[i];
            let eval = evals.as_ref()[i];
            comms_minus_evals.push(commitment + (P1::neg_generator() * eval));
        }

        let proof_lincomb = P1::lincomb(&proofs, &rpowers);
        let proof_z_lincomb = P1::lincomb(proofs, points_mul_rpowers);

        let comm_minus_eval_lincomb = P1::lincomb(comms_minus_evals, rpowers);

        bls::verify_pairings(
            (proof_lincomb, self.g2_monomial[1]),
            (comm_minus_eval_lincomb + proof_z_lincomb, P2::generator()),
        )
    }

    fn blob_to_commitment_inner(&self, blob: &Blob<G1>) -> Commitment {
        blob.commitment(self)
    }

    pub fn blob_to_commitment(&self, blob: impl AsRef<[u8]>) -> Result<Commitment, BlobError> {
        let blob = Blob::<G1>::from_slice(blob)?;
        let commitment = self.blob_to_commitment_inner(&blob);
        Ok(commitment)
    }

    fn blob_proof_inner(&self, blob: &Blob<G1>, commitment: &Commitment) -> Proof {
        blob.proof(commitment, self)
    }

    pub fn blob_proof(&self, blob: impl AsRef<[u8]>, commitment: &Bytes48) -> Result<Proof, Error> {
        let blob: Blob<G1> = Blob::from_slice(blob).map_err(Error::from)?;
        let commitment = Commitment::decompress(commitment)
            .map_err(|err| Error::from(BlsError::ECGroup(err)))?;
        let proof = self.blob_proof_inner(&blob, &commitment);
        Ok(proof)
    }

    pub fn proof(&self, blob: impl AsRef<[u8]>, point: &Bytes32) -> Result<(Proof, Fr), Error> {
        let blob: Blob<G1> = Blob::from_slice(blob).map_err(Error::from)?;
        let point =
            Fr::from_be_slice(point).map_err(|err| Error::from(BlsError::FiniteField(err)))?;

        let poly = Polynomial(&blob.elements);
        let (eval, proof) = poly.prove(point, self);

        Ok((proof, eval))
    }

    fn verify_blob_proof_inner(
        &self,
        blob: &Blob<G1>,
        commitment: &Commitment,
        proof: &Proof,
    ) -> bool {
        let poly = Polynomial(&blob.elements);
        let challenge = blob.challenge(commitment);
        let eval = poly.evaluate(challenge, self);
        self.verify_proof_inner(proof, commitment, &challenge, &eval)
    }

    pub fn verify_blob_proof(
        &self,
        blob: impl AsRef<[u8]>,
        commitment: &Bytes48,
        proof: &Bytes48,
    ) -> Result<bool, Error> {
        let blob: Blob<G1> = Blob::from_slice(blob).map_err(Error::from)?;
        let commitment = Commitment::decompress(commitment)
            .map_err(|err| Error::from(BlsError::ECGroup(err)))?;
        let proof = Proof::decompress(proof).map_err(|err| Error::from(BlsError::ECGroup(err)))?;

        let verified = self.verify_blob_proof_inner(&blob, &commitment, &proof);
        Ok(verified)
    }

    fn verify_blob_proof_batch_inner(
        &self,
        blobs: impl AsRef<[Blob<G1>]>,
        commitments: impl AsRef<[Commitment]>,
        proofs: impl AsRef<[Proof]>,
    ) -> bool {
        assert_eq!(blobs.as_ref().len(), commitments.as_ref().len());
        assert_eq!(commitments.as_ref().len(), proofs.as_ref().len());

        let mut challenges = Vec::with_capacity(blobs.as_ref().len());
        let mut evaluations = Vec::with_capacity(blobs.as_ref().len());

        for i in 0..blobs.as_ref().len() {
            let poly = Polynomial(&blobs.as_ref()[i].elements);
            let challenge = blobs.as_ref()[i].challenge(&commitments.as_ref()[i]);
            let eval = poly.evaluate(challenge, self);

            challenges.push(challenge);
            evaluations.push(eval);
        }

        self.verify_proof_batch(proofs, commitments, challenges, evaluations)
    }

    pub fn verify_blob_proof_batch<B>(
        &self,
        blobs: impl AsRef<[B]>,
        commitments: impl AsRef<[Bytes48]>,
        proofs: impl AsRef<[Bytes48]>,
    ) -> Result<bool, Error>
    where
        B: AsRef<[u8]>,
    {
        assert_eq!(blobs.as_ref().len(), commitments.as_ref().len());
        assert_eq!(commitments.as_ref().len(), proofs.as_ref().len());

        let blobs: Result<Vec<Blob<G1>>, _> =
            blobs.as_ref().iter().map(Blob::<G1>::from_slice).collect();
        let blobs = blobs.map_err(Error::from)?;

        let commitments: Result<Vec<Commitment>, _> = commitments
            .as_ref()
            .iter()
            .map(Commitment::decompress)
            .collect();
        let commitments = commitments.map_err(|err| Error::from(BlsError::ECGroup(err)))?;

        let proofs: Result<Vec<Proof>, _> =
            proofs.as_ref().iter().map(Proof::decompress).collect();
        let proofs = proofs.map_err(|err| Error::from(BlsError::ECGroup(err)))?;

        let verified = self.verify_blob_proof_batch_inner(blobs, commitments, proofs);
        Ok(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{bls::Compress, kzg::spec::{
        BlobToCommitment, ComputeBlobProof, ComputeProof, VerifyBlobProof, VerifyBlobProofBatch,
        VerifyProof,
    }};

    use std::{
        fs::{self, File},
        io::BufReader,
        path::PathBuf,
        sync::Arc,
    };

    const FIELD_ELEMENTS_PER_BLOB: usize = 4096;
    const SETUP_G2_LEN: usize = 65;

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

        for file in consensus_spec_test_files("compute_kzg_proof") {
            let reader = BufReader::new(file);
            let case: ComputeProof = serde_yaml::from_reader(reader).unwrap();

            let expected = case.output();
            let Some((blob, z)) = case.input() else {
                assert!(expected.is_none());
                continue;
            };
            let Ok((proof, y)) = setup.proof(blob, &z) else {
                assert!(expected.is_none());
                continue;
            };
            let (expected_proof, expected_y) = expected.unwrap();
            let mut proof_bytes = [0u8; Proof::BYTES];
            proof.compress(&mut proof_bytes).unwrap();
            assert_eq!(proof_bytes, expected_proof);
            assert_eq!(y.to_be_bytes(), expected_y);
        }
    }

    #[test]
    fn compute_blob_kzg_proof() {
        let setup = setup();
        let setup = Arc::new(setup);

        for file in consensus_spec_test_files("compute_blob_kzg_proof") {
            let reader = BufReader::new(file);
            let case: ComputeBlobProof = serde_yaml::from_reader(reader).unwrap();

            let expected = case.output();
            let Some((blob, commitment)) = case.input() else {
                assert!(expected.is_none());
                continue;
            };
            let Ok(proof) = setup.blob_proof(&blob, &commitment) else {
                assert!(expected.is_none());
                continue;
            };
            let expected = expected.unwrap();
            let mut proof_bytes = [0u8; Proof::BYTES];
            proof.compress(&mut proof_bytes).unwrap();
            assert_eq!(proof_bytes, expected);
        }
    }

    #[test]
    fn blob_to_commitment() {
        // load trusted setup
        let setup = setup();
        let setup = Arc::new(setup);

        for file in consensus_spec_test_files("blob_to_kzg_commitment") {
            let reader = BufReader::new(file);
            let case: BlobToCommitment = serde_yaml::from_reader(reader).unwrap();

            let expected = case.output();
            let Ok(commitment) = setup.blob_to_commitment(case.input()) else {
                assert!(expected.is_none());
                continue;
            };
            let expected = expected.unwrap();
            let mut commitment_bytes = [0u8; Commitment::BYTES];
            commitment.compress(&mut commitment_bytes).unwrap();
            assert_eq!(commitment_bytes, expected);
        }
    }

    #[test]
    fn verify_kzg_proof() {
        // load trusted setup
        let setup = setup();
        let setup = Arc::new(setup);

        for file in consensus_spec_test_files("verify_kzg_proof") {
            let reader = BufReader::new(file);
            let case: VerifyProof = serde_yaml::from_reader(reader).unwrap();

            let expected = case.output();
            let Some((commitment, z, y, proof)) = case.input() else {
                assert!(expected.is_none());
                continue;
            };
            let Ok(verified) = setup.verify_proof(&proof, &commitment, &z, &y) else {
                assert!(expected.is_none());
                continue;
            };
            let expected = expected.unwrap();
            assert_eq!(verified, expected);
        }
    }

    #[test]
    fn verify_blob_kzg_proof() {
        // load trusted setup
        let setup = setup();
        let setup = Arc::new(setup);

        for file in consensus_spec_test_files("verify_blob_kzg_proof") {
            let reader = BufReader::new(file);
            let case: VerifyBlobProof = serde_yaml::from_reader(reader).unwrap();

            let expected = case.output();
            let Some((blob, commitment, proof)) = case.input() else {
                assert!(expected.is_none());
                continue;
            };
            let Ok(verified) = setup.verify_blob_proof(&blob, &commitment, &proof) else {
                assert!(expected.is_none());
                continue;
            };
            let expected = expected.unwrap();
            assert_eq!(verified, expected);
        }
    }

    #[test]
    fn verify_blob_kzg_proof_batch() {
        // load trusted setup
        let setup = setup();
        let setup = Arc::new(setup);

        for file in consensus_spec_test_files("verify_blob_kzg_proof_batch") {
            let reader = BufReader::new(file);
            let case: VerifyBlobProofBatch = serde_yaml::from_reader(reader).unwrap();

            let expected = case.output();
            let Some((blobs, commitments, proofs)) = case.input() else {
                assert!(expected.is_none());
                continue;
            };
            let Ok(verified) = setup.verify_blob_proof_batch(&blobs, &commitments, &proofs) else {
                assert!(expected.is_none());
                continue;
            };
            let expected = expected.unwrap();
            assert_eq!(verified, expected);
        }
    }
}
