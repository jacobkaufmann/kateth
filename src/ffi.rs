use core::slice;

use crate::{
    bls::Fr,
    kzg::{Bytes32, Bytes48, Commitment, Proof, Setup},
};

pub type EthBlob = [u8; 131072];

#[repr(transparent)]
pub struct EthSetup(Setup<4096, 65>);

#[repr(C)]
pub struct KzgProofAndEval {
    proof: Proof,
    eval: Fr,
}

#[no_mangle]
pub extern "C" fn compute_kzg_proof(
    setup: &EthSetup,
    blob: &EthBlob,
    z: &Bytes32,
) -> KzgProofAndEval {
    let (proof, eval) = setup.0.proof(blob, z).unwrap();
    KzgProofAndEval { proof, eval }
}

#[no_mangle]
pub extern "C" fn verify_kzg_proof(
    setup: &EthSetup,
    commitment: &Bytes48,
    z: &Bytes32,
    y: &Bytes32,
    proof: &Bytes48,
) -> bool {
    setup.0.verify_proof(proof, commitment, z, y).unwrap()
}

#[no_mangle]
pub extern "C" fn blob_to_kzg_commitment(setup: &EthSetup, blob: &EthBlob) -> Commitment {
    setup.0.blob_to_commitment(blob).unwrap()
}

#[no_mangle]
pub extern "C" fn compute_blob_kzg_proof(
    setup: &EthSetup,
    blob: &EthBlob,
    commitment: &Bytes48,
) -> Proof {
    setup.0.blob_proof(blob, commitment).unwrap()
}

#[no_mangle]
pub extern "C" fn verify_blob_kzg_proof(
    setup: &EthSetup,
    blob: &EthBlob,
    commitment: &Bytes48,
    proof: &Bytes48,
) -> bool {
    setup.0.verify_blob_proof(blob, commitment, proof).unwrap()
}

#[no_mangle]
pub extern "C" fn verify_blob_kzg_proof_batch(
    setup: &EthSetup,
    blobs: *const EthBlob,
    commitments: *const Bytes48,
    proofs: *const Bytes48,
    n: usize,
) -> bool {
    let blobs = unsafe { slice::from_raw_parts(blobs, n) };
    let commitments = unsafe { slice::from_raw_parts(commitments, n) };
    let proofs = unsafe { slice::from_raw_parts(proofs, n) };
    setup
        .0
        .verify_blob_proof_batch(blobs, commitments, proofs)
        .unwrap()
}
