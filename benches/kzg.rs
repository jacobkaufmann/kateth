use kateth::{
    blob::Blob,
    kzg::{Commitment, Proof, Setup},
    Compress,
};

use criterion::{criterion_group, criterion_main, BatchSize, BenchmarkId, Criterion, Throughput};
use rand::thread_rng;

pub fn benchmark(c: &mut Criterion) {
    let path = format!("{}/trusted_setup_4096.json", env!("CARGO_MANIFEST_DIR"));
    let kzg = Setup::<4096, 65>::load_json(path).unwrap();

    let batch_sizes = [1usize, 2, 4, 8, 16, 32, 64, 128];
    let max_batch_size = *batch_sizes.last().unwrap();

    let mut rng = thread_rng();
    let blobs: Vec<Vec<u8>> = (0..max_batch_size)
        .map(|_| Blob::<4096>::random(&mut rng).to_bytes())
        .collect();
    let mut commitments = Vec::with_capacity(blobs.len());
    let mut proofs = Vec::with_capacity(blobs.len());
    for blob in &blobs {
        let commitment = kzg.blob_to_commitment(blob).unwrap();
        let mut bytes = [0u8; Commitment::COMPRESSED];
        commitment.compress(&mut bytes).unwrap();
        commitments.push(bytes);

        let proof = kzg.blob_proof(blob, &bytes).unwrap();
        let mut bytes = [0u8; Proof::COMPRESSED];
        proof.compress(&mut bytes).unwrap();
        proofs.push(bytes);
    }

    c.bench_function("blob to kzg commitment", |b| {
        b.iter(|| kzg.blob_to_commitment(&blobs[0]))
    });
    c.bench_function("compute blob kzg proof", |b| {
        b.iter(|| kzg.blob_proof(&blobs[0], &commitments[0]))
    });
    c.bench_function("verify blob kzg proof", |b| {
        b.iter(|| kzg.verify_blob_proof(&blobs[0], &commitments[0], &proofs[0]))
    });

    let mut group = c.benchmark_group("verify blob kzg proof batch");
    for size in batch_sizes {
        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, &size| {
            b.iter_batched_ref(
                || {
                    (
                        blobs[..size].to_vec(),
                        commitments[..size].to_vec(),
                        proofs[..size].to_vec(),
                    )
                },
                |(blobs, commitments, proofs)| {
                    kzg.verify_blob_proof_batch(blobs, commitments, proofs)
                },
                BatchSize::LargeInput,
            );
        });
    }
    group.finish();
}

criterion_group!(benches, benchmark);
criterion_main!(benches);
