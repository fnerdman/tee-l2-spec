# TEE Attestation and PKI Model

This section describes the attestation mechanism and verification process for TEE block builders.

## Overview

A block builder running in a TEE uses attestation to prove to verifiers that it is running the expected code in a genuine TEE. This creates a verifiable chain of trust from hardware to block signatures, enabling anyone to verify that blocks were produced by an attested TEE running authorized code.

## Design Goals

The TEE block proof system aims to provide:

1. **Integrity**: Guarantee that blocks are built according to the expected rules
2. **Verifiability**: Allow any party to verify block provenance without trusting the operator
3. **Transparency**: Provide visibility into the code running inside the TEE
4. **No Availability Assumptions**: Prevent any single entity from becoming a verification bottleneck

## Attestation Mechanism

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

## Workload Identity Derivation

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

### Deterministic Key Derivation

The certificate issuance process uses a deterministic key derivation approach:

1. When a block builder node starts and completes TEE attestation, it first sends its attestation quote to the coordinator
2. The coordinator verifies the attestation quote and derives a unique seed based on the block builder's workload identity:
   `derived_seed = HMAC-SHA256(coordinator_master_seed, workload_identity)`
3. The coordinator securely transmits this derived seed to the block builder
4. The block builder uses this seed to deterministically generate its key pair inside the TEE
5. The block builder creates a CSR with this key pair and sends it to the coordinator
6. The coordinator signs the certificate and returns it

This approach ensures cryptographic binding between the attestation process and the block builder's identity, while enabling deterministic key recovery if needed.

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

The key pair generated using the derived seed is used for both block signing and TLS connections:

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

This certificate serves two purposes:
1. It authenticates TLS connections to the block builder service
2. It provides the public key used to verify block signatures

When a client connects to a block builder service:
1. The TLS handshake occurs using the attested certificate
2. The client verifies the certificate is signed by an authorized coordinator
3. The same verification path used for blocks can be applied to the connection

This approach unifies the security model for both block verification and service connectivity, using the same trust chain for both.

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

This model eliminates the CA component but requires verifiers to process more complex attestation data. It is generally preferred for high-security environments where elimination of intermediaries is desired.