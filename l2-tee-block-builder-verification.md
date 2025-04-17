# L2 TEE Block Builder Verification Protocol

## Introduction

This specification describes the attestation and verification protocol for TEE-based L2 block builders. The protocol enables verifiable and transparent guarantees of block production within Trusted Execution Environments (TEEs), allowing any party to verify that blocks were produced according to the expected rules without trusting the operator.

## Design Goals

The L2 TEE Block Builder Verification protocol aims to provide:

1. **Integrity**: Guarantee that blocks are built according to the expected rules
2. **Verifiability**: Allow any party to verify block provenance without trusting the operator
3. **Transparency**: Provide visibility into the code running inside the TEE
4. **No Availability Assumptions**: Prevent any single entity from becoming a verification bottleneck

## Protocol Components

The protocol consists of three key components:

1. **TEE Attestation**: Mechanism to prove that a block builder is running inside a genuine TEE with the expected code
2. **Block Signatures**: Method for signing blocks inside the TEE and verifying these signatures
3. **Expected Measurements**: System for publishing and verifying trusted code configurations

## TEE Attestation Mechanism

Attestation is the process by which a TEE proves its identity and integrity. The protocol uses Intel TDX with DCAP (Data Center Attestation Primitives) attestation.

### Intel TDX DCAP Attestation

TDX attestation produces a Quote structure that contains:

```
TDXQuote {
  Header: QuoteHeader,       // Version and attestation key type info
  TDReport: TDReport,        // TD measurement registers
  TEEExtendedProductID: u16, // TEE product identifier
  TEESecurityVersion: u16,   // Security patch level
  QESecurityVersion: u16,    // Quoting Enclave security version
  QEVendorID: [16]byte,      // Intel Quoting Enclave vendor ID
  UserData: [64]byte,        // User-defined report data (public key hash)
  Signature: byte[],         // ECDSA signature over the Quote
}

TDReport {
  MRTD: [48]byte,           // Measurement register for TD (initial code/data)
  RTMR: [4][48]byte,        // Runtime measurement registers
  MROWNER: [48]byte,        // Measurement register for owner (policy)
  MRCONFIGID: [48]byte,     // Configuration ID
  MROWNER_CONFIG: [48]byte, // Owner-defined configuration
  ReportData: [64]byte      // User-defined data (public key hash)
}
```

The attestation process follows these steps:

1. The TEE generates a TD Report containing its measurement registers and report data
2. The Quote Enclave (QE) creates a Quote by signing the TD Report with an Attestation Key
3. The Quote can be verified against Intel's Provisioning Certification Service (PCS)

### Attestation Endorsements

To validate a TDX Quote, a verifier needs these endorsements:

```
DCAPEndorsements {
  QEIdentity: byte[],       // Quoting Enclave Identity
  TCBInfo: byte[],          // Trusted Computing Base info
  QECertificationData: byte[] // Certification data for the attestation key
}
```

These endorsements provide the trust anchor for the Intel attestation infrastructure.

## Workload Identity and Key Management

### Workload Identity Derivation

A TEE's workload identity is derived from a combination of its measurement registers. The TDX platform provides several registers that capture different aspects of the workload:

```
struct TDXMeasurements {
    bytes MRTD;             // Initial TD measurement (boot loader, initial data)
    bytes[4] RTMR;          // Runtime measurements (extended at runtime)
    bytes MROWNER;          // Owner measurement (trusted policies)
    bytes MRCONFIGID;       // Configuration ID (unique ID of the VVD/configuration)
    bytes MROWNERCONFIG;    // Owner-defined configuration (includes authorized pubkeys)
}
```

The workload identity computation takes these registers into account:

```
function ComputeTDXWorkloadIdentity(quote *TDXQuote) ([32]byte, error) {
    // Extract TDReport from the quote
    tdReport := quote.TDReport
    
    // Primary identity is derived from measurement registers
    // RTMRs contain the runtime measurements of the workload code
    // MROWNER contains the TD owner's policy
    // MROWNERCONFIG contains the owner-defined configuration
    identity := SHA256(
        tdReport.RTMR[0] || 
        tdReport.RTMR[1] || 
        tdReport.RTMR[2] || 
        tdReport.RTMR[3] ||
        tdReport.MROWNER ||
        tdReport.MROWNERCONFIG
    )
    
    return identity
}
```

The MROWNERCONFIG register is particularly important as it can contain:
- References to authorized administrator public keys
- Network configuration parameters
- Access control policies
- Other runtime configuration values

All of these values are captured in the workload identity hash, ensuring that any change to the configuration results in a different identity that must be explicitly authorized.

### Extended Identity with Operator

For certain applications, the operator's identity can be combined with the workload identity:

```
function ComputeExtendedIdentity(workloadIdentity [32]byte, operatorAddress [20]byte) ([32]byte, error) {
    // Combine workload and operator identity
    return SHA256(workloadIdentity || operatorAddress)
}
```

This extended identity ensures that only specific operators are authorized to run particular workloads.

### Deterministic Key Derivation

The key generation process uses a deterministic approach:

1. When a block builder node starts and completes TEE attestation, it first sends its attestation quote to the coordinator
2. The coordinator verifies the attestation quote and derives a unique seed based on the block builder's workload identity:
   `derived_seed = HMAC-SHA256(coordinator_master_seed, workload_identity)`
3. The coordinator securely transmits this derived seed to the block builder
4. The block builder uses this seed to deterministically generate its key pair inside the TEE
5. The block builder creates a CSR with this key pair and sends it to the coordinator
6. The coordinator signs the certificate and returns it

This approach enables deterministic key recovery and creates a cryptographic binding between the workload identity and the block builder's keys.

## Block Signatures and Verification

### Block Signing Process

When producing blocks, the TEE-protected block builder:

1. Generates a block according to the L2 protocol rules
2. Computes the block hash (`BlockHash = hash_tree_root(block)`)
3. Signs the block hash with its private key (derived from the coordinator-provided seed)
4. The signature, along with verification material, forms a "TEE proof"

### TEE Proof Structure

There are two types of TEE proofs depending on the verification model:

#### PKI-based TEE Proof
```
struct PKITEEProof {
    bytes blockHash;         // Hash of the block being proven
    bytes signature;         // Signature over blockHash using TEE-protected key
    bytes certificate;       // X.509 certificate signed by coordinator
}
```

#### Direct Attestation TEE Proof
```
struct DirectTEEProof {
    bytes blockHash;         // Hash of the block being proven
    bytes signature;         // Signature over blockHash using TEE-protected key
    bytes32 attestationHash; // Hash of the attestation record stored on-chain
}
```

### Block Verification

To verify a block with a PKI-based TEE proof:

```
function VerifyBlockWithPKI(block, teeProof, coordinatorPublicKeys, expectedMeasurements) {
    // 1. Verify block hash matches the hash in the proof
    computedHash = hash_tree_root(block)
    if computedHash != teeProof.blockHash {
        return false
    }
    
    // 2. Verify certificate was signed by an authorized coordinator
    if !VerifyCertificateSignature(teeProof.certificate, coordinatorPublicKeys) {
        return false
    }
    
    // 3. Verify block signature using certificate's public key
    if !VerifySignature(teeProof.blockHash, teeProof.signature, teeProof.certificate.PublicKey) {
        return false
    }
    
    // Note: No explicit workload identity verification is needed here
    // as the coordinator has already verified the attestation during
    // certificate issuance
    
    return true
}
```

## Certificate Authority Model

In the PKI model, a coordinator running in its own TEE acts as a Certificate Authority (CA):

1. The coordinator generates a CA key pair within its TEE
2. The coordinator publishes its attestation on-chain using Automata DCAP Attestation
3. The coordinator's public key is published as part of the attestation
4. Verifiers check that the coordinator's attestation matches expected measurements

### On-Chain DCAP Attestation for Coordinator

To establish trust in the coordinator, its TEE attestation is verified on-chain:

```solidity
// Sample interaction with Automata DCAP Attestation
function registerCoordinator(bytes calldata rawQuote) external onlyGovernance {
    // Verify the DCAP quote on-chain
    bool isValid = IDCAPAttestation(DCAP_ATTESTATION_CONTRACT).verifyAndAttestOnChain(rawQuote);
    require(isValid, "Invalid DCAP quote");
    
    // Extract public key from quote's report data
    bytes memory publicKey = extractPublicKeyFromQuote(rawQuote);
    
    // Extract workload identity from quote
    bytes32 workloadIdentity = extractWorkloadIdentityFromQuote(rawQuote);
    
    // Check if this is an authorized coordinator workload
    require(isAuthorizedCoordinator(workloadIdentity), "Unauthorized coordinator");
    
    // Register the coordinator
    coordinatorPublicKeys[workloadIdentity] = publicKey;
    
    emit CoordinatorRegistered(workloadIdentity, publicKey);
}
```

This approach leverages Automata's on-chain DCAP attestation to verify the coordinator's quote directly on-chain, ensuring that:

1. The quote is genuine and signed by Intel
2. The coordinator is running in a legitimate TEE
3. The coordinator is running authorized code
4. The coordinator's public key is authenticated

### Certificate Issuance Process

When a block builder node starts:

1. It requests an attestation quote from the TDX platform
2. It sends the attestation quote to the coordinator
3. The coordinator verifies:
   - The attestation signature is valid using Intel's endorsements
   - The attestation's measurements match an authorized workload identity
4. If verification succeeds, the coordinator derives a unique seed for the block builder based on its workload identity and securely transmits it
5. The block builder generates its key pair deterministically using the derived seed inside the TEE
6. The block builder creates a CSR containing its public key and sends it to the coordinator
7. The coordinator verifies the CSR is valid and created with the expected public key
8. The coordinator signs the certificate and returns it

Note that the coordinator does not need to separately verify if the workload identity is authorized, as this verification is implicitly performed during the registration of the coordinator itself. Since the coordinator is only registered if it runs authorized code, and it verifies the validity of the attestation, there is no need for additional authorization checks.

### Attested TLS Certificates

The same key pair used for block signing is also used for TLS connections:

```
X.509 Certificate {
    Version: 3
    Serial Number: <Random value>
    Subject: CN=BlockBuilderNode, O=L2TEEBuilder
    Issuer: CN=TEECoordinator, O=L2TEECoordinator
    Validity:
        Not Before: <Issue time>
        Not After: <Issue time + 7 days>
    Subject Public Key Info:
        Public Key Algorithm: ECDSA
        Public Key: <Builder's ECDSA public key>
    Extensions:
        SubjectAltName:
            DNS: builder.example.com
            IP: 192.0.2.1
        Authority Key Identifier: <Coordinator key ID>
        Subject Key Identifier: <Builder key ID>
        X509v3 Extended Key Usage:
            TLS Web Server Authentication
            TLS Web Client Authentication
        Custom Extension OID 1.3.6.1.4.1.12345.1.1: <WorkloadIdentity>
        Custom Extension OID 1.3.6.1.4.1.12345.1.2: <OperatorID> (optional)
    Signature Algorithm: ECDSA-SHA256
    Signature: <Coordinator's signature>
}
```

## Service Connectivity and TLS Authentication

Beyond block verification, secure communication with TEE services is critical. The protocol uses the same trust chain for both block signatures and service connectivity.

### Rollup Boost Integration

Rollup Boost, as the block builder sidecar for the L2 sequencer, verifies blocks from the TEE block builder using the same verification mechanism:

1. When Rollup Boost establishes a connection to the TEE block builder, it performs TLS verification using the coordinator's CA certificate
2. During handshake, it obtains and verifies the block builder's certificate and public key
3. When receiving blocks from the builder, Rollup Boost verifies the block signatures using the public key from the TLS certificate
4. This ensures that blocks accepted by Rollup Boost were produced by the attested TEE with the expected workload identity

This seamless integration leverages the PKI infrastructure to ensure that only blocks from valid TEE builders are accepted by the rollup sequencer.

### TLS Connection Verification

When a client connects to a block builder service:

```
function VerifyTLSConnection(tlsCertificate, coordinators) {
    // 1. Verify certificate chain
    if !VerifyCertificateChain(tlsCertificate, coordinators) {
        return "Invalid certificate chain"
    }
    
    // 2. Check certificate revocation status
    if IsRevoked(tlsCertificate.SerialNumber) {
        return "Certificate revoked"
    }
    
    // 3. Extract public key for future block verification
    builderPublicKey = tlsCertificate.PublicKey
    
    // Note: No explicit workload identity verification is needed here
    // as the coordinator has already verified the attestation when
    // issuing the certificate
    
    return "Connection verified", builderPublicKey
}
```

### Block Proof/Service Identity Alignment

A critical security property is the alignment between block signatures and service identity:

1. When a client connects to a block builder service, it obtains the service's public key from the TLS certificate
2. This same public key is used to verify blocks produced by that builder
3. Both the TLS certificate and block signatures are verified against the same trust chain (coordinator attestation)

This ensures that a block builder cannot produce valid blocks with a signature that doesn't match its service identity, preventing identity spoofing attacks.

## Expected Measurements and On-Chain Verification

### Expected Measurement Definition

TEE measurements are hardware-enforced hashes of the code and initial data loaded into the TEE. For Intel TDX these include:

```
struct ExpectedMeasurement {
    bytes32 workloadIdentity;     // The derived workload identity hash
    uint64 startBlock;            // L2 block height from which this measurement is valid
    uint64 endBlock;              // L2 block height until which this measurement is valid
    bytes32 codeCommitHash;       // Git commit hash of source code
    bytes32 buildInfoHash;        // Hash of build information and dependencies
    string metadataURI;           // URI to additional metadata (build instructions, etc.)
}
```

The workload identity encompasses all measurement registers including MRTD, RTMRs, MROWNER, MRCONFIGID, and MROWNERCONFIG, ensuring that any change to the code, configuration, or policy results in a different identity that must be explicitly authorized.

### On-Chain Verification System

To securely track and verify expected measurements, the protocol leverages an on-chain verification system:

```solidity
contract TEEMeasurementRegistry {
    // Registry of expected measurements indexed by workload identity
    mapping(bytes32 => ExpectedMeasurement) public expectedMeasurements;
    
    // Registry of coordinator attestations verified through DCAP
    mapping(bytes32 => CoordinatorInfo) public verifiedCoordinators;
    
    // Automata DCAP Attestation contract reference
    IDCAPAttestation public dcapAttestationContract;
    
    struct CoordinatorInfo {
        bytes32 workloadIdentity;
        bytes publicKey;
        uint64 registrationTime;
        uint64 expirationTime;
        bool active;
    }
    
    // Register a coordinator after verifying its DCAP quote on-chain
    function registerCoordinator(bytes calldata rawQuote) external onlyGovernance {
        // Verify the DCAP quote on-chain using Automata's verification
        bool isValid = dcapAttestationContract.verifyAndAttestOnChain(rawQuote);
        require(isValid, "Invalid DCAP quote");
        
        // Extract workload identity and public key from the quote
        bytes32 workloadIdentity = extractWorkloadIdentityFromQuote(rawQuote);
        bytes memory publicKey = extractPublicKeyFromQuote(rawQuote);
        
        // Verify this is an expected coordinator measurement
        require(isExpectedCoordinator(workloadIdentity), "Unauthorized coordinator");
        
        // Register the coordinator
        verifiedCoordinators[workloadIdentity] = CoordinatorInfo({
            workloadIdentity: workloadIdentity,
            publicKey: publicKey,
            registrationTime: uint64(block.timestamp),
            expirationTime: uint64(block.timestamp + 30 days), // Example validity period
            active: true
        });
        
        emit CoordinatorRegistered(workloadIdentity, publicKey);
    }
    
    // Additional functions for measurement management
    // ...
}
```

### Reproducible Builds

To establish trust in expected measurements, the TEE block builder must be built using a reproducible build process:

1. **Source Code Publication**: The full source code is published with a specific commit hash
2. **Build Environment**: A deterministic build environment is defined (specific compiler versions, dependencies, etc.)
3. **Build Instructions**: Step-by-step instructions to reproduce the build are published
4. **Verification**: Independent parties can follow the build process and verify that it produces the same measurements

## Verification Models

The protocol supports two verification models:

### 1. PKI Model with TEE Coordinator

In this model:
1. A coordinator running in a TEE serves as a Certificate Authority
2. The coordinator verifies quotes against expected measurements
3. If valid, the coordinator signs certificates for block builders
4. Verifiers trust certificates signed by the coordinator

This approach simplifies verification for light clients but introduces the coordinator as a component.

### 2. Direct On-Chain Attestation

As an alternative:
1. Block builders publish their attestations directly on-chain
2. Block proofs reference these attestations by hash
3. Verifiers check attestations against on-chain expected measurements

This model eliminates the CA component but requires verifiers to process more complex attestation data.

## Security Considerations

Several security considerations should be noted:

1. **Time of Check/Time of Use**: A malicious operator could try to upgrade the TEE to a compromised version after attestation. To prevent this, block verification should check that the proof corresponds to the expected measurement at the time the block was produced.

2. **Endorsement Freshness**: DCAP endorsements have validity periods. Verifiers must ensure they use up-to-date endorsements from Intel's PCS.

3. **Key Compromise**: If a TEE's private key is compromised, the block production system must have a process to revoke certificates and update expected measurements.

4. **Chain of Trust**: The security of the entire system depends on the integrity of the attestation mechanism, the correctness of expected measurements, and the proper implementation of the verification protocol.