# Block Signatures and Verification Process

## Overview

This document details the signature and verification mechanisms used to prove that blocks were produced by attested TEE block builders. The design enables any party to cryptographically verify block provenance without trusting the operator.

## Block Signing

### Key Material and Deterministic Key Derivation

Block builders use two separate key pairs:
1. An ephemeral ECDSA key pair for TLS communications
2. A deterministic ECDSA key pair for block signing

The block signing keys are generated deterministically within the TEE:

1. After successful attestation and establishment of a secure TLS connection, the coordinator derives a unique seed for the block builder:
   ```
   derived_seed = HMAC-SHA256(coordinator_master_seed, workload_identity)
   ```

2. The block builder uses this seed to deterministically generate its signing key pair inside the TEE:
   ```
   (signingPrivateKey, signingPublicKey) = DeriveECDSAKeypair(derived_seed)
   ```

3. The signing private key never leaves the TEE, while the signing public key is included in a dedicated block signing certificate signed by the coordinator

This deterministic approach ensures that:
- The same workload identity always produces the same signing key pair
- The signing key can be regenerated after TEE restarts without external storage
- The signing key material is cryptographically bound to the attested workload identity

### Block Signing Process

When building a block, the TEE block builder:

1. Produces a block according to the L2 protocol rules
2. Computes the signature target using the `ComputeSignatureTarget` function:
   ```
   function ComputeSignatureTarget(block, transactions) {
       // Create ordered list of all transaction hashes
       transactionHashes = []
       for each tx in transactions:
           txHash = keccak256(rlp_encode(tx))
           transactionHashes.append(txHash)
       
       // Compute a single hash over block data and transaction hashes
       // This ensures the signature covers the exact transaction set and order
       return keccak256(abi.encode(
           block.parentHash,
           block.number,
           block.timestamp,
           transactionHashes
       ))
   }
   
   signatureTarget = ComputeSignatureTarget(block, block.transactions)
   ```

   This signature target formulation provides a balance between rollup compatibility and verification strength:
   
   - Contains the minimal set of elements needed to uniquely identify a block's contents
   - Compatible with data available on L1 for most optimistic and ZK rollup implementations
   - Enables signature verification without requiring state root dependencies
   - Supports future L1 verification of block authenticity across different rollup designs
   
   By focusing on transaction ordering and chain position rather than state transitions, this approach offers practical verification capabilities for TEE-produced blocks.

3. Signs the signature target using its private key:
   ```
   signature = ECDSA_Sign(privateKey, signatureTarget)
   ```

### Signature Inclusion within Block

To include the TEE signature within the block itself (making it verifiable on L1), the signature is added as a special final transaction in the block:

```
SignatureTransaction {
    // Standard transaction fields with special values
    to: TEE_SIGNATURE_CONTRACT_ADDRESS,
    from: TEE_BUILDER_ADDRESS,
    value: 0,
    
    // The signature data is included in the transaction input
    data: abi.encode(
        signature
    )
}
```

This approach has several advantages:
1. It works with standard L2 block structures without protocol changes
2. The signature is included in data posted to L1 as part of the rollup process
3. It creates a permanent on-chain record verifiable by any party
4. It maintains compatibility across different L2 implementations

After adding the signature transaction, the final block and signature are sent to the requestor (e.g., Rollup Boost)

## Block Verification

Blocks can be verified using one of two methods, depending on the verification model used:

### PKI-based Verification

In the PKI model, verifiers use the coordinator's CA certificate to establish a chain of trust:

```
function VerifyBlockWithPKI(block, signingCertificate, coordinatorCACert, endorsements) {
    // 1. Verify the signing certificate was signed by a trusted coordinator
    if !VerifyCertificateChain(signingCertificate, coordinatorCACert) {
        return false
    }
    
    // 2. Extract the builder's signing public key from the certificate
    signingPublicKey = signingCertificate.PublicKey
    
    // 3. Get the final signature transaction
    signatureTx = block.transactions[block.transactions.length - 1]
    
    // 4. Extract signature from the transaction
    signature = abi.decode(signatureTx.data)
    
    // 5. Get all transactions except the final signature transaction
    normalTransactions = block.transactions.slice(0, block.transactions.length - 1)
    
    // 6. Compute the signature target
    computedTarget = ComputeSignatureTarget(block, normalTransactions)
    
    // 7. Verify the signature using the signing public key
    if !ECDSA_Verify(signingPublicKey, computedTarget, signature) {
        return false
    }
    
    // 8. Verify the TDX attestation from certificate extension
    tdxQuote = signingCertificate.Extensions["TDXQuote"]
    
    // 8a. Verify the DCAP attestation signature with Intel endorsements
    if !VerifyAttestationSignature(tdxQuote, endorsements) {
        return false
    }
    
    // 8b. Verify the public key hash in quote matches the certificate's
    reportData = tdxQuote.TDReport.ReportData
    publicKeyHash = SHA256(signingPublicKey)
    if !ConstantTimeEquals(reportData[:32], publicKeyHash) {
        return false
    }
    
    // 8c. Derive and verify workload identity against expected measurements
    workloadIdentity = DeriveWorkloadIdentity(tdxQuote)
    if !IsExpectedMeasurement(workloadIdentity) {
        return false
    }
    
    return true
}
```

### Direct Attestation Verification

For higher security use cases, verifiers can directly verify against attestations without relying on the coordinator's certificate:

```
function VerifyBlockWithDirectAttestation(block, tdxQuote, endorsements, expectedMeasurements, signingPublicKey) {
    // 1. Verify the DCAP attestation signature with Intel endorsements
    if !VerifyAttestationSignature(tdxQuote, endorsements) {
        return false
    }
    
    // 2. Derive workload identity from TDX quote
    workloadIdentity = DeriveWorkloadIdentity(tdxQuote)
    
    // 3. Verify workload identity is authorized
    if !IsExpectedMeasurement(workloadIdentity, expectedMeasurements) {
        return false
    }
    
    // 4. Verify the public key hash in quote matches the provided signing public key
    reportData = tdxQuote.TDReport.ReportData
    publicKeyHash = SHA256(signingPublicKey)
    if !ConstantTimeEquals(reportData[:32], publicKeyHash) {
        return false
    }
    
    // 5. Get the final signature transaction
    signatureTx = block.transactions[block.transactions.length - 1]
    
    // 6. Extract signature from the transaction
    signature = abi.decode(signatureTx.data)
    
    // 7. Get all transactions except the final signature transaction
    normalTransactions = block.transactions.slice(0, block.transactions.length - 1)
    
    // 8. Compute the signature target
    computedTarget = ComputeSignatureTarget(block, normalTransactions)
    
    // 9. Verify the signature using the signing public key
    if !ECDSA_Verify(signingPublicKey, computedTarget, signature) {
        return false
    }
    
    return true
}
```

## Rollup Boost Integration

Rollup Boost serves as a block builder sidecar for L2 chains, connecting the sequencer to external block builders. When integrating with TEE block builders, Rollup Boost implements the following verification flow:

1. **TLS Connection Establishment**:
   - Rollup Boost connects to the TEE block builder using TLS
   - It verifies the builder's ephemeral TLS certificate against the coordinator's CA certificate
   - The TLS connection is used for secure communication with the block builder

2. **Block Signing Certificate Retrieval**:
   - Rollup Boost retrieves the block builder's signing certificate via a public endpoint
   - This can be a simple HTTP endpoint like `/signing-certificate`
   - The signing certificate's authenticity is verified through its signature by the coordinator:
     ```
     function RetrieveSigningCertificate() {
         // Fetch the block signing certificate from the public endpoint
         signingCertificate = FetchFromEndpoint("/signing-certificate")
         
         // Verify the signing certificate against the coordinator's CA
         if !VerifyCertificateChain(signingCertificate, coordinatorCACert) {
             return error("Invalid signing certificate")
         }
         
         // Extract and store the signing public key
         signingPublicKey = signingCertificate.PublicKey
         
         return signingPublicKey
     }
     ```

3. **Block Request and Verification**:
   - When Rollup Boost receives a block from the builder:
     ```
     function VerifyBuilderBlock(block) {
         // Use the signing public key from the verified certificate
         signingPublicKey = storedSigningCertificate.PublicKey
         
         // Get the final signature transaction
         signatureTx = block.transactions[block.transactions.length - 1]
         
         // Extract signature from the transaction
         signature = abi.decode(signatureTx.data)
         
         // Get all transactions except the final signature transaction
         normalTransactions = block.transactions.slice(0, block.transactions.length - 1)
         
         // Compute the signature target
         computedTarget = ComputeSignatureTarget(block, normalTransactions)
         
         // Verify signature
         return ECDSA_Verify(signingPublicKey, computedTarget, signature)
     }
     ```

4. **Block Forwarding**:
   - If verification passes, Rollup Boost forwards the block to the sequencer
   - If verification fails, Rollup Boost falls back to the local block production

This verification process ensures that:
- Only blocks from attested TEE builders are accepted
- The TLS connection provides secure communication with the block builder
- The block signing certificate is independently verified through the coordinator's signature
- The block signature verification uses the deterministic signing key derived from the coordinator-provided seed
- There's end-to-end verification from block production to inclusion in the L2 chain

This verification process additionally ensures that:
1. The signature transaction is properly formatted
2. The signature covers the block without the final transaction
3. The signature is valid for the attested TEE block builder
4. The signature is included in the rollup data posted to L1

## Verification Tool

A command-line tool is provided for manual verification of blocks:

```
verify-tee-block \
  --block-file=block.json \
  --mode=pki \
  --signing-cert-file=builder-signing-cert.pem \
  --ca-cert-file=coordinator-ca.pem \
  --endorsements-file=intel-endorsements.json \
  --expected-measurements-file=measurements.json
```

For direct attestation verification, the tool can be used with the quote directly:

```
verify-tee-block \
  --block-file=block.json \
  --mode=direct \
  --tdx-quote-file=quote.bin \
  --signing-public-key=key.pem \
  --endorsements-file=intel-endorsements.json \
  --expected-measurements-file=measurements.json
```

The verification tool supports both PKI-based and direct attestation verification modes, allowing operators and users to independently verify that blocks were produced by attested TEE environments.

## Security Considerations

1. **Certificate Revocation**: Certificates have a short validity period (e.g., 7 days) to minimize the impact of key compromise. Additionally, a certificate revocation list (CRL) is maintained by the coordinator.

2. **Time of Check/Time of Use (TOCTOU)**: Block verification checks that the workload identity was valid at the time the block was produced, preventing attacks where a malicious operator might try to use a revoked measurement.

3. **Replay Protection**: Block signatures include block numbers and parent hashes, preventing replay attacks where an attacker might try to reuse signatures from previous blocks.

4. **Key Rotation**: Even though keys are derived deterministically, regular rotation schedules can be implemented by including a time component in the seed derivation.
