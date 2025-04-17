# Block Signatures and Verification Process

## Overview

This document details the signature and verification mechanisms used to prove that blocks were produced by attested TEE block builders. The design enables any party to cryptographically verify block provenance without trusting the operator.

## Block Signing

### Key Material and Deterministic Key Derivation

Block builders use ECDSA keys for signing blocks. These keys are generated deterministically within the TEE:

1. After successful attestation, the coordinator derives a unique seed for the block builder:
   ```
   derived_seed = HMAC-SHA256(coordinator_master_seed, workload_identity)
   ```

2. The block builder uses this seed to deterministically generate its key pair inside the TEE:
   ```
   (privateKey, publicKey) = DeriveECDSAKeypair(derived_seed)
   ```

3. The private key never leaves the TEE, while the public key is included in the certificate signed by the coordinator

This deterministic approach ensures that:
- The same workload identity always produces the same key pair
- The key can be regenerated after TEE restarts without external storage
- Key material is cryptographically bound to the attested workload identity

### Block Signing Process

When building a block, the TEE block builder:

1. Produces a block according to the L2 protocol rules
2. Computes the block hash:
   ```
   blockHash = keccak256(rlp_encode(block))
   ```
3. Signs the block hash using its private key:
   ```
   signature = ECDSA_Sign(privateKey, blockHash)
   ```
4. The block, its hash, and the signature are sent to the requestor (e.g., Rollup Boost)

## Block Verification

Blocks can be verified using one of two methods, depending on the verification model used:

### PKI-based Verification

In the PKI model, verifiers use the coordinator's CA certificate to establish a chain of trust:

```
function VerifyBlockWithPKI(block, signature, certificate, coordinatorCACert) {
    // 1. Verify the certificate was signed by a trusted coordinator
    if !VerifyCertificateChain(certificate, coordinatorCACert) {
        return false
    }
    
    // 2. Extract the builder's public key from the certificate
    publicKey = certificate.PublicKey
    
    // 3. Compute the block hash
    blockHash = keccak256(rlp_encode(block))
    
    // 4. Verify the signature using the public key
    if !ECDSA_Verify(publicKey, blockHash, signature) {
        return false
    }
    
    // 5. (Optional) Extract and verify workload identity from certificate
    workloadIdentity = certificate.Extensions["WorkloadIdentity"]
    if !IsExpectedMeasurement(workloadIdentity) {
        return false
    }
    
    return true
}
```

### Direct Attestation Verification

For higher security use cases, verifiers can directly verify against attestations:

```
function VerifyBlockWithDirectAttestation(block, signature, attestation, expectedMeasurements) {
    // 1. Verify the attestation is valid
    if !VerifyAttestation(attestation) {
        return false
    }
    
    // 2. Extract workload identity from attestation
    workloadIdentity = DeriveWorkloadIdentity(attestation)
    
    // 3. Verify workload identity is authorized
    if !IsExpectedMeasurement(workloadIdentity, expectedMeasurements) {
        return false
    }
    
    // 4. Extract the public key from attestation user data
    publicKey = ExtractPublicKey(attestation.UserData)
    
    // 5. Compute the block hash
    blockHash = keccak256(rlp_encode(block))
    
    // 6. Verify the signature using the public key
    if !ECDSA_Verify(publicKey, blockHash, signature) {
        return false
    }
    
    return true
}
```

## Rollup Boost Integration

Rollup Boost serves as a block builder sidecar for L2 chains, connecting the sequencer to external block builders. When integrating with TEE block builders, Rollup Boost implements the following verification flow:

1. **TLS Connection Establishment**:
   - Rollup Boost connects to the TEE block builder using TLS
   - It verifies the builder's TLS certificate against the coordinator's CA certificate
   - During the handshake, it obtains the builder's certificate and public key

2. **Block Request and Verification**:
   - When Rollup Boost receives a block from the builder:
     ```
     function VerifyBuilderBlock(block, signature) {
         // Use the public key obtained during TLS handshake
         publicKey = storedTLSCertificate.PublicKey
         
         // Compute block hash
         blockHash = keccak256(rlp_encode(block))
         
         // Verify signature
         return ECDSA_Verify(publicKey, blockHash, signature)
     }
     ```

3. **Block Forwarding**:
   - If verification passes, Rollup Boost forwards the block to the sequencer
   - If verification fails, Rollup Boost falls back to the local block production

This verification process ensures that:
- Only blocks from attested TEE builders are accepted
- The block signature verification uses the same public key as the TLS connection
- There's end-to-end verification from block production to inclusion in the L2 chain

## Verification Tool

A command-line tool is provided for manual verification of blocks:

```
verify-tee-block \
  --block-file=block.json \
  --signature-file=signature.bin \
  --certificate-file=builder-cert.pem \
  --ca-cert-file=coordinator-ca.pem \
  --expected-measurements-file=measurements.json
```

The verification tool supports both PKI-based and direct attestation verification modes, allowing operators and users to independently verify that blocks were produced by attested TEE environments.

## Security Considerations

1. **Certificate Revocation**: Certificates have a short validity period (e.g., 7 days) to minimize the impact of key compromise. Additionally, a certificate revocation list (CRL) is maintained by the coordinator.

2. **Time of Check/Time of Use (TOCTOU)**: Block verification checks that the workload identity was valid at the time the block was produced, preventing attacks where a malicious operator might try to use a revoked measurement.

3. **Replay Protection**: Block signatures include block numbers and parent hashes, preventing replay attacks where an attacker might try to reuse signatures from previous blocks.

4. **Key Rotation**: Even though keys are derived deterministically, regular rotation schedules can be implemented by including a time component in the seed derivation.