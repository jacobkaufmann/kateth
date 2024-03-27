#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct Setup_4096__65 Setup_4096__65;

typedef P1 Proof;

typedef blst_fr Fr;
#define Fr_BITS 256
#define Fr_BYTES (Fr_BITS / 8)

typedef struct KzgProofAndEval {
  Proof proof;
  Fr eval;
} KzgProofAndEval;

typedef struct Setup_4096__65 EthSetup;

typedef uint8_t EthBlob[131072];

typedef uint8_t Bytes32[32];

typedef uint8_t Bytes48[48];

typedef P1 Commitment;

struct KzgProofAndEval compute_kzg_proof(const EthSetup *setup,
                                         const EthBlob *blob,
                                         const Bytes32 *z);

bool verify_kzg_proof(const EthSetup *setup,
                      const Bytes48 *commitment,
                      const Bytes32 *z,
                      const Bytes32 *y,
                      const Bytes48 *proof);

Commitment blob_to_kzg_commitment(const EthSetup *setup, const EthBlob *blob);

Proof compute_blob_kzg_proof(const EthSetup *setup, const EthBlob *blob, const Bytes48 *commitment);

bool verify_blob_kzg_proof(const EthSetup *setup,
                           const EthBlob *blob,
                           const Bytes48 *commitment,
                           const Bytes48 *proof);

bool verify_blob_kzg_proof_batch(const EthSetup *setup,
                                 const EthBlob *blobs,
                                 const Bytes48 *commitments,
                                 const Bytes48 *proofs,
                                 uintptr_t n);
