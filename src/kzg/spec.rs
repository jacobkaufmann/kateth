use serde::Deserialize;

use crate::{
    bls::{Compress, Fr, P1},
    bytes::Bytes,
};

use super::{Bytes32, Bytes48};

fn bytes32_from_bytes(bytes: &Bytes) -> Option<Bytes32> {
    let bytes: Option<[u8; Fr::BYTES]> = TryFrom::try_from(bytes.as_ref()).ok();
    bytes.map(Into::<Bytes32>::into)
}

fn bytes48_from_bytes(bytes: &Bytes) -> Option<Bytes48> {
    let bytes: Option<[u8; P1::COMPRESSED]> = TryFrom::try_from(bytes.as_ref()).ok();
    bytes.map(Into::<Bytes48>::into)
}

#[derive(Deserialize)]
struct BlobToCommitmentInput {
    blob: Bytes,
}

#[derive(Deserialize)]
pub struct BlobToCommitment {
    input: BlobToCommitmentInput,
    output: Option<Bytes>,
}

impl BlobToCommitment {
    pub fn input(&self) -> Bytes {
        self.input.blob.clone()
    }

    pub fn output(&self) -> Option<Bytes48> {
        self.output.as_ref().and_then(bytes48_from_bytes)
    }
}

#[derive(Deserialize)]
struct ComputeBlobProofInput {
    blob: Bytes,
    commitment: Bytes,
}

#[derive(Deserialize)]
pub struct ComputeBlobProof {
    input: ComputeBlobProofInput,
    output: Option<Bytes>,
}

impl ComputeBlobProof {
    fn commitment(&self) -> Option<Bytes48> {
        bytes48_from_bytes(&self.input.commitment)
    }

    pub fn input(&self) -> Option<(Bytes, Bytes48)> {
        Some(self.input.blob.clone()).zip(self.commitment())
    }

    pub fn output(&self) -> Option<Bytes48> {
        self.output.as_ref().and_then(bytes48_from_bytes)
    }
}

#[derive(Deserialize)]
struct ComputeProofInput {
    blob: Bytes,
    z: Bytes,
}

#[derive(Deserialize)]
pub struct ComputeProof {
    input: ComputeProofInput,
    output: Option<(Bytes, Bytes)>,
}

impl ComputeProof {
    fn z(&self) -> Option<Bytes32> {
        bytes32_from_bytes(&self.input.z)
    }

    pub fn input(&self) -> Option<(Bytes, Bytes32)> {
        Some(self.input.blob.clone()).zip(self.z())
    }

    pub fn output(&self) -> Option<(Bytes48, Bytes32)> {
        self.output.as_ref().and_then(|(proof, y)| {
            let proof = bytes48_from_bytes(proof);
            let y = bytes32_from_bytes(y);
            proof.zip(y)
        })
    }
}

#[derive(Deserialize)]
struct VerifyBlobProofInput {
    blob: Bytes,
    commitment: Bytes,
    proof: Bytes,
}

#[derive(Deserialize)]
pub struct VerifyBlobProof {
    input: VerifyBlobProofInput,
    output: Option<bool>,
}

impl VerifyBlobProof {
    fn commitment(&self) -> Option<Bytes48> {
        bytes48_from_bytes(&self.input.commitment)
    }

    fn proof(&self) -> Option<Bytes48> {
        bytes48_from_bytes(&self.input.proof)
    }

    pub fn input(&self) -> Option<(Bytes, Bytes48, Bytes48)> {
        match (self.commitment(), self.proof()) {
            (Some(commitment), Some(proof)) => Some((self.input.blob.clone(), commitment, proof)),
            _ => None,
        }
    }

    pub fn output(&self) -> Option<bool> {
        self.output
    }
}

#[derive(Deserialize)]
struct VerifyProofInput {
    commitment: Bytes,
    z: Bytes,
    y: Bytes,
    proof: Bytes,
}

#[derive(Deserialize)]
pub struct VerifyProof {
    input: VerifyProofInput,
    output: Option<bool>,
}

impl VerifyProof {
    fn commitment(&self) -> Option<Bytes48> {
        bytes48_from_bytes(&self.input.commitment)
    }

    fn z(&self) -> Option<Bytes32> {
        bytes32_from_bytes(&self.input.z)
    }

    fn y(&self) -> Option<Bytes32> {
        bytes32_from_bytes(&self.input.y)
    }

    fn proof(&self) -> Option<Bytes48> {
        bytes48_from_bytes(&self.input.proof)
    }

    pub fn input(&self) -> Option<(Bytes48, Bytes32, Bytes32, Bytes48)> {
        match (self.commitment(), self.z(), self.y(), self.proof()) {
            (Some(commitment), Some(z), Some(y), Some(proof)) => Some((commitment, z, y, proof)),
            _ => None,
        }
    }

    pub fn output(&self) -> Option<bool> {
        self.output
    }
}

#[derive(Deserialize)]
struct VerifyBlobProofBatchInput {
    blobs: Vec<Bytes>,
    commitments: Vec<Bytes>,
    proofs: Vec<Bytes>,
}

#[derive(Deserialize)]
pub struct VerifyBlobProofBatch {
    input: VerifyBlobProofBatchInput,
    output: Option<bool>,
}

impl VerifyBlobProofBatch {
    fn commitments(&self) -> Option<Vec<Bytes48>> {
        let commitments: Vec<Bytes48> = self
            .input
            .commitments
            .iter()
            .filter_map(bytes48_from_bytes)
            .collect();
        (commitments.len() == self.input.commitments.len()).then_some(commitments)
    }

    fn proofs(&self) -> Option<Vec<Bytes48>> {
        let proofs: Vec<Bytes48> = self
            .input
            .proofs
            .iter()
            .filter_map(bytes48_from_bytes)
            .collect();
        (proofs.len() == self.input.proofs.len()).then_some(proofs)
    }

    pub fn input(&self) -> Option<(Vec<Bytes>, Vec<Bytes48>, Vec<Bytes48>)> {
        match (self.commitments(), self.proofs()) {
            (Some(commitments), Some(proofs)) => (self.input.blobs.len() == commitments.len()
                && commitments.len() == proofs.len())
            .then_some((self.input.blobs.clone(), commitments, proofs)),
            _ => None,
        }
    }

    pub fn output(&self) -> Option<bool> {
        self.output
    }
}
