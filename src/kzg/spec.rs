use alloy_primitives::{Bytes, FixedBytes};
use serde::Deserialize;

use crate::{
    blob::Blob,
    bls::{Fr, P1},
};

use super::{Commitment, Proof};

fn blob_from_bytes<const N: usize>(bytes: &Bytes) -> Option<Blob<N>> {
    Blob::<N>::from_slice(bytes.as_ref()).ok()
}

fn fr_from_bytes(bytes: &Bytes) -> Option<Fr> {
    let bytes = FixedBytes::<{ Fr::BYTES }>::try_from(bytes.as_ref()).ok();
    bytes.and_then(Fr::from_be_bytes)
}

fn p1_from_bytes(bytes: &Bytes) -> Option<P1> {
    let bytes = FixedBytes::<{ P1::BYTES }>::try_from(bytes.as_ref()).ok()?;
    P1::deserialize(&bytes).ok()
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
    pub fn input<const N: usize>(&self) -> Option<Blob<N>> {
        blob_from_bytes(&self.input.blob)
    }

    pub fn output(&self) -> Option<Commitment> {
        self.output.as_ref().and_then(p1_from_bytes)
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
    fn blob<const N: usize>(&self) -> Option<Blob<N>> {
        blob_from_bytes(&self.input.blob)
    }

    fn commitment(&self) -> Option<Commitment> {
        p1_from_bytes(&self.input.commitment)
    }

    pub fn input<const N: usize>(&self) -> Option<(Blob<N>, Commitment)> {
        self.blob().zip(self.commitment())
    }

    pub fn output(&self) -> Option<Proof> {
        self.output.as_ref().and_then(p1_from_bytes)
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
    fn blob<const N: usize>(&self) -> Option<Blob<N>> {
        blob_from_bytes(&self.input.blob)
    }

    fn z(&self) -> Option<Fr> {
        fr_from_bytes(&self.input.z)
    }

    pub fn input<const N: usize>(&self) -> Option<(Blob<N>, Fr)> {
        self.blob().zip(self.z())
    }

    pub fn output(&self) -> Option<(Proof, Fr)> {
        self.output.as_ref().and_then(|(proof, y)| {
            let proof = p1_from_bytes(proof);
            let y = fr_from_bytes(y);
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
    fn blob<const N: usize>(&self) -> Option<Blob<N>> {
        blob_from_bytes(&self.input.blob)
    }

    fn commitment(&self) -> Option<Commitment> {
        p1_from_bytes(&self.input.commitment)
    }

    fn proof(&self) -> Option<Proof> {
        p1_from_bytes(&self.input.proof)
    }

    pub fn input<const N: usize>(&self) -> Option<(Blob<N>, Commitment, Proof)> {
        match (self.blob(), self.commitment(), self.proof()) {
            (Some(blob), Some(commitment), Some(proof)) => Some((blob, commitment, proof)),
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
    fn commitment(&self) -> Option<Commitment> {
        p1_from_bytes(&self.input.commitment)
    }

    fn z(&self) -> Option<Fr> {
        fr_from_bytes(&self.input.z)
    }

    fn y(&self) -> Option<Fr> {
        fr_from_bytes(&self.input.y)
    }

    fn proof(&self) -> Option<Proof> {
        p1_from_bytes(&self.input.proof)
    }

    pub fn input(&self) -> Option<(Commitment, Fr, Fr, Proof)> {
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
    fn blobs<const N: usize>(&self) -> Option<Vec<Blob<N>>> {
        let blobs: Vec<Blob<N>> = self
            .input
            .blobs
            .iter()
            .filter_map(blob_from_bytes)
            .collect();
        (blobs.len() == self.input.blobs.len()).then_some(blobs)
    }

    fn commitments(&self) -> Option<Vec<Commitment>> {
        let commitments: Vec<Commitment> = self
            .input
            .commitments
            .iter()
            .filter_map(p1_from_bytes)
            .collect();
        (commitments.len() == self.input.commitments.len()).then_some(commitments)
    }

    fn proofs(&self) -> Option<Vec<Proof>> {
        let proofs: Vec<Proof> = self.input.proofs.iter().filter_map(p1_from_bytes).collect();
        (proofs.len() == self.input.proofs.len()).then_some(proofs)
    }

    pub fn input<const N: usize>(&self) -> Option<(Vec<Blob<N>>, Vec<Commitment>, Vec<Proof>)> {
        match (self.blobs(), self.commitments(), self.proofs()) {
            (Some(blobs), Some(commitments), Some(proofs)) => (blobs.len() == commitments.len()
                && commitments.len() == proofs.len())
            .then_some((blobs, commitments, proofs)),
            _ => None,
        }
    }

    pub fn output(&self) -> Option<bool> {
        self.output
    }
}
