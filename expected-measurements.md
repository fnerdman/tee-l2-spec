# Expected Measurements

This section describes how expected measurements are defined, published, and used to verify TEE block builders.

## Overview

Expected measurements are cryptographic references to trusted code configurations that are allowed to produce blocks. They form the foundation of trust in the TEE block building system by providing a standard against which attestations can be verified.

## Measurement Definition

### Hardware Measurements

TEE measurements are hardware-enforced hashes of the code and initial data loaded into the TEE. For Intel TDX:

```
struct TDXMeasurements {
    bytes MRTD;             // Initial TD measurement (boot loader, initial data)
    bytes[4] RTMR;          // Runtime measurements (extended at runtime)
    bytes MROWNER;          // Contains operator's public key (Ethereum address or other identifier)
    bytes MRCONFIGID;       // Hash of service configuration stored onchain and fetched on boot
    bytes MROWNERCONFIG;    // Contains unique instance ID chosen by the operator
}
```

These measurements are collected by the hardware during TEE initialization and cannot be forged by software.

### Workload Identity

From these hardware measurements, a deterministic workload identity is derived:

```
function DeriveWorkloadIdentity(measurements TDXMeasurements) bytes32 {
    return SHA256(
        measurements.MRTD    ||
        measurements.RTMR[0] ||
        measurements.RTMR[1] || 
        measurements.RTMR[2] || 
        measurements.RTMR[3] ||
        measurements.MROWNER ||
        measurements.MROWNERCONFIG ||
        measurements.MRCONFIGID
    );
}
```

The workload identity encompasses all measurement registers including MRTD, RTMRs, MROWNER, MRCONFIGID, and MROWNERCONFIG, ensuring that any change to the code, configuration, or operator results in a different identity that must be explicitly authorized.

These measurement registers serve specific purposes in the permissioned attestation model:

- **MROWNER**: Contains the operator's public key (Ethereum address or other identifier), establishing who is authorized to run this instance
- **MROWNERCONFIG**: Contains a unique instance ID chosen by the operator, which the operator must sign to authenticate itself
- **MRCONFIGID**: Contains a hash of the actual service configuration that is stored onchain and fetched during boot

This permissioned model ensures that only authorized operators can run authorized workloads. The TEE enforces this by requiring operator authentication via signature verification of the instance ID before proceeding with registration.

## On-Chain Verification System

To securely track and verify expected measurements, the protocol leverages an on-chain verification system:

```solidity
contract TEEMeasurementRegistry {
    // Registry of expected measurements indexed by workload identity
    mapping(bytes32 => ExpectedMeasurement) public expectedMeasurements;
    
    // Registry of coordinator attestations verified through DCAP
    mapping(bytes32 => CoordinatorInfo) public verifiedCoordinators;
    
    // Automata DCAP Attestation contract reference
    IDCAPAttestation public dcapAttestationContract;
    
    struct ExpectedMeasurement {
        bytes32 workloadIdentity;     // The derived workload identity hash
        uint64 startBlock;            // L2 block height from which this measurement is valid
        uint64 endBlock;              // L2 block height until which this measurement is valid
        bytes32 codeCommitHash;       // Git commit hash of source code
        bytes32 buildInfoHash;        // Hash of build information and dependencies
        string metadataURI;           // URI to additional metadata (build instructions, etc.)
    }
    
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

This registry serves as the source of truth for:

1. Expected TEE measurements for both coordinators and block builders
2. Verified coordinator attestations and public keys
3. Block builder authorization status

## Reproducible Builds

To establish trust in expected measurements, the TEE block builder must be built using a reproducible build process:

1. **Source Code Publication**: The full source code is published with a specific commit hash
2. **Build Environment**: A deterministic build environment is defined (specific compiler versions, dependencies, etc.)
3. **Build Instructions**: Step-by-step instructions to reproduce the build are published
4. **Verification**: Independent parties can follow the build process and verify that it produces the same measurements

This allows anyone to verify that the expected measurements correspond to the published source code.

## Measurement Lifecycle

Expected measurements follow a defined lifecycle:

1. **Proposal**: New measurements are proposed with documentation of code changes
2. **Review**: The changes and build process are publicly reviewed
3. **Testing**: The new version is tested in a staging environment
4. **Publication**: Approved measurements are added to the registry with a future start block
5. **Transition**: Both old and new measurements are valid during the transition period
6. **Deprecation**: Old measurements are eventually deprecated by setting an end block

## Measurement Updates

Updates to expected measurements are required in several scenarios:

1. **Security Patches**: Critical security fixes require immediate updates
2. **Feature Additions**: New functionality requires code changes
3. **Library Updates**: Dependencies need to be updated periodically
4. **Configuration Changes**: Protocol parameters may change

The update process ensures that:

1. The security of the system is maintained during transitions
2. Users have sufficient notice of pending changes
3. Independent verification is possible before adoption

## Security Considerations

Several security considerations apply to expected measurements:

1. **Measurement Precision**: Measurements must be specific enough to identify the exact code but flexible enough to allow for irrelevant variations (like build timestamps)

2. **Update Timing**: Updates must be scheduled to allow sufficient time for verification but quick enough to address security issues

3. **Revocation**: The system must allow for emergency revocation of compromised measurements

4. **Governance Security**: The governance mechanism for updating measurements must be secure against takeover attempts

5. **Build Reproducibility**: Minor differences in build environments can lead to different measurements, creating false negatives in verification
