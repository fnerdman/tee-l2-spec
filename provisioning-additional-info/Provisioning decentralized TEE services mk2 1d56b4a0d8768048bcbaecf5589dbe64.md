# Provisioning decentralized TEE services mk2

Tags: Andromeda
Created: April 14, 2025 11:55 AM
Type: Design Doc

Background context: [[OLD] Exploring provisioning of decentralized TEE services](https://www.notion.so/OLD-Exploring-provisioning-of-decentralized-TEE-services-1af6b4a0d87680c9b8a1d509990481e6?pvs=21) 

Implementation: https://github.com/Ruteri/tee-service-provisioning-backend

**Glossary**

By **service provisioning** I will mean the process by which a freshly deployed confidential virtual machine (TDX VM) becomes a live instance of an application. This consists of any steps that need to be taken from the VM boot to the application being ready to process requests as expected. Some example steps would include decrypting disks, fetching dynamic configuration and secrets, configuring firewalls and ingresses.

- Changelog
    
    April 22, 2025: added a note about [Operator configuration](https://www.notion.so/Operator-configuration-1dd6b4a0d876801eacd7d47a64544d9d?pvs=21) 
    

# Problem

Creating a decentralized service comes with some non-trivial choices and tradeoffs.

**Application Governance**: who decides what about the application? Who, and how, controls the release cycle for the application? Who controls configurations, allowed operators?

**Data Availability**: how, and where from, are instances of an application receiving their configuration and secrets? How does availability of secrets and configuration affect the application?

**Service Discovery**: how to discover and authenticate applications, instances, peers?

Why provisioning decentralized services is an unsolved problem is that all of the currently available provisioning tools (ansible, terraform, consul, kubernetes) assume central, trusted operators and administrators. We can’t allow unchecked admin privilege in our decentralized systems!

How decentralized a system is can be impacted in a big way by the three aspects of service provisioning mentioned above. With decentralization, as with security, the system is only as decentralized as its least decentralized part. If data availability rests on a centralized server, then the system as a whole is centralized as a result — and the same of course applies to governance and service discovery.

# Requirements

**Tailored decentralization:** It’s important to keep decentralization properties at corresponding levels. Forcing service provisioning that has wildly different decentralization properties from the service itself will be inefficient and will create friction — whether it’s much more or much less decentralized.

This applies especially to the governance *model* — who controls what and how. The governance model should be consistent throughout the application, provisioning included.

This means that both data availability and service discovery should not assume or require specific decentralization properties, and should simply be fit to measure.

Sometimes, transparency is all that is needed. Other times, everything should be a DAO vote.

**Scalability:** Provisioning system should be able to serve any number of applications with no additional effort. This is crucial as we expand our TEE service offering, and our current tools simply do not allow us to scale.

**Disaster recovery:** Provisioning system, as well as provisioned systems, must be able to withstand bugs, outages and faults. While the specific disaster recovery properties will be dictated by the application’s requirements for decentralization and availability, provisioning system itself should not negatively affect ability to recover from a disaster.

# Guidelines

More malleable than requirements, guidelines are the product of our experience.

**Onchain Governance:** The only real way to perform governance in a decentralized, or even properly transparent way. While we want to tailor decentralization guarantees to apps — they are free to pick their governance model, all apps must be governed onchain.

**TLS-First:** ATLS is not scalable enough, and there is no real reason to use attested tls for most connections. Performing attestation out of band and relying on regular tls certificates in all hot paths is much preferred for performance and ease of use.

**Keep public IPs in DNS:** Similar to the above point, we don’t have to reinvent the wheel when it comes to discovering public endpoints for applications: just keep them in DNS records. This, maybe counterintuitively, does not have any negative impact on liveness or decentralization properties in practice, as IPs and instances are anyway fully controlled by respective infrastructure operators.

**Service discovery, not network topology:** Do not assume a specific network topology, since we will not find a good enough fit for our applications. Instead, allow service and public endpoint discovery for bootstrapping any network topology the application needs. If IPs have to be kept confidential, either put them encrypted into DNS, or put TEE-aware bootnodes in DNS and use those to discover peers.

**Multiple, content-addressed, data availability backends:** While onchain governance is one-size-fits-all, the same cannot be said of any data availability (storage) backend. Some applications will prefer something like onchain L2 storage, while some others would much prefer github or S3, or even vault, for their DA. This comes down to a fundamental availability vs confidentiality tradeoff, especially when it comes to secrets, and we cannot pick in advance.

The big benefit of using content addressing is that we decouple data from any specific storage, which means we can mirror all the data as necessary to avoid both lock-in and liveness assumptions.

# Proposed Solution

On a high level:

1. Onchain governed PKI: per application certificate signing authority that will only sign applications whitelisted by governance contract (measurement+operator). The PKI must integrate some kind of KMS to store the CA private key.
2. Onchain governance interface for applications to follow, that includes in particular:
    1. attested certificate authority for the application (from PKI) to authenticate connections
    2. allowed measurements and operators
    3. configuration and secret data backends to fetch configs and secrets from
    4. dynamic configuration and secrets to resolve for a given instance (measurement+operator)
    5. list of dns entries for service and instance discovery and network bootstrap
    
    This will likely change slightly depending on the application, but the above should all be relevant to our current products. If changes are necessary the interface will be made modular (object capability model).
    
3. Chain-aware provisioning backend allowing instances to bootstrap themselves, and for clients to request the attested certificate authority along with application instances (note to self: could be separated).
4. Instance provisioning agent to use the provisioning API and KMS.
5. Configuration and secrets data backends: onchain storage, github, S3, ipfs, vault.
6. Shamir’s secret sharing–based KMS with an administrator client. Not onchain (yet).

### **Architecture and components diagram**

![image.png](Provisioning%20decentralized%20TEE%20services%20mk2%201d56b4a0d8768048bcbaecf5589dbe64/image.png)

### Design Details

- Application governance contract
    
    See https://github.com/Ruteri/tee-service-provisioning-backend/blob/main/src/OnchainRegistry.sol and https://pkg.go.dev/github.com/ruteri/tee-service-provisioning-backend/registry
    
    1. Application PKI
        
        ```solidity
        struct AppPKI {
        	bytes ca;
        	bytes pubkey;
        	bytes attestation;
        }
        
        interface WorkloadGovernance {
        		// Governance sets the PKI once, verifying the attestation out of band
        		// Any user who choses to can also verify the attestation:
        		// 1. Get the attestation data from AppPKI
        		// 2. Extract measurements and report data from the attestation
        		// 3. Verify report data is as expected, defined elsewhere
        		// 4. Verify measurement matches the expected one (KMS contract)
            function getPKI() external view returns (AppPKI memory);
        }
        ```
        
    2. Managing measurements and operators
        
        ```solidity
        struct DCAPEvent {
        		uint32 Index;
        		uint32 EventType;
        		bytes EventPayload;
        		bytes32 Digest;
        }
        
        struct DCAPReport {
        	  // All fields are expected to be 48 bytes
        		bytes mrTd;          // Measurement register for TD
        		bytes[4] RTMRs;      // Runtime measurement registers
        		bytes mrOwner;       // Measurement register for owner
        		bytes mrConfigId;    // Measurement register for config ID
        		bytes mrConfigOwner; // Measurement register for config owner
        }
        
        struct MAAReport {
        		bytes32[24] PCRs;
        }
        
        interface WorkloadGovernance {
        		// Maps DCAP report to a workload identity, usually hash of RTMRs[0..3]
            ComputeDCAPIdentity(report *DCAPReport) ([32]byte, error)
            // Maps MAA report to a workload identity, usually hash of PCRs[4,9,11]
            ComputeMAAIdentity(report *MAAReport) ([32]byte, error)
            // Whitelisted identities and operators (optional)
            IdentityAllowed(bytes32 identity, address operator) (bool)
        }
        ```
        
    
    1. Managing configurations, discovery and data availability
        
        ```solidity
        interface PorvisioningGovernance {
            // Configuration mapping for identity
            getConfigForIdentity(bytes32 identity, address operator) (bytes32)
            // Public instances — API and p2p bootstrap
            allInstanceDomainNames() (string[])
            // Storage backend management
            allStorageBackends() (string[])
        }
        ```
        
- Provisioning API
    
    See https://pkg.go.dev/github.com/ruteri/tee-service-provisioning-backend/api/provisioner
    
    ### Registration Process
    
    When a TEE instance requests registration:
    
    1. The instance submits a certificate signing request through an attested channel
    2. The provisioning handler computes the workload identity from measurements
    3. The provisioning handler checks if this identity is whitelisted in the on-chain registry
    4. If authorized, the provisioning handler requests KMS to sign the CSR
    5. The provisioning handler processes the configuration template, resolving references and decrypting secrets
    6. The system returns the signed certificate, resolved configuration, and a deterministic private key for derivation of secrets
    
    ### Operator Signature Extension
    
    The system supports an optional additional authorization mechanism through operator signatures:
    
    1. When enabled, the TEE instance generates a keypair and exposes its public key
    2. An authorized operator signs the instance's public key using their Ethereum private key
    3. The signature is embedded in the CSR as an X.509 extension
    4. During registration, the handler extracts the signature and recovers the operator's Ethereum address
    5. The system checks if this operator is authorized to provision instances with the given identity
    6. Registration proceeds only if both the TEE identity and operator signature are valid
    
    This two-factor authorization (attestation + operator signature) provides enhanced security
    for sensitive deployments and allows for explicit operator approval of each instance.
    
    ### Configuration Template Processing
    
    The Handler resolves two types of references in configuration templates:
    
    - Config references (format: `__CONFIG_REF_<hash>`) - Replaced with content from storage
    - Secret references (format: `__SECRET_REF_<hash>`) - Replaced with decrypted secret content
    
    Secrets are pre-encrypted and only decrypted during the provisioning process
    for authorized TEE instances.
    
    Note: secrets could also be stored encrypted in-place if more convenient.
    
- Metadata API
    
    `func (h *[Handler](https://pkg.go.dev/github.com/ruteri/tee-service-provisioning-backend@v0.0.0-20250411113500-c482f2756905/api/provisioner#Handler)) HandleAppMetadata(w [http](https://pkg.go.dev/net/http).[ResponseWriter](https://pkg.go.dev/net/http#ResponseWriter), r *[http](https://pkg.go.dev/net/http).[Request](https://pkg.go.dev/net/http#Request))`
    
    Retrieves application metadata for a specified contract address. It provides (attested) certificate authority for the application, secrets encryption pubkey, and associated DNS records.
    
    URL format: `GET /api/public/app_metadata/{contract_address}`
    
    Response: JSON-encoded `api.MetadataResponse`:
    
    ```go
    package api
    
    type MetadataResponse struct {
    	// CACert is the certificate authority that is expected for the application
    	CACert interfaces.CACert `json:"ca_cert"`
    
    	// AppPubkey is the applications public key used for encrypting secrets
    	AppPubkey interfaces.AppPubkey `json:"app_pubkey"`
    
    	// DomainNames is the domain names that should be resolved to get app instances
    	DomainNames []interfaces.AppDomainName `json:"domain_names"`
    
    	// Attestation is the quote for AppAddress||sha256(CACert||AppPubkey) (52 bytes)
    	Attestation interfaces.Attestation `json:"attestaion"`
    }
    ```
    
- KMS API
    
    See https://pkg.go.dev/github.com/ruteri/tee-service-provisioning-backend/kms
    
    The KMS package is responsible for managing cryptographic keys, certificates,
    and attestations for TEE instances. It also provides the cryptographic materials
    needed for secure secret management. It implements the interfaces.KMS interface:
    
    ```go
    // KMS defines the interface for key management operations
    type KMS interface {
    	// GetPKI *derives* the CA certificate, app pubkey and attests them for a given contract
    	// CA and pubkey should match the ones in the certificate (must match unless rotated)
    	// Anyone should be able to fetch the PKI through an attested channel, therefore the attestation is only provided as trace/transparency
    	GetPKI(contractAddr ContractAddress) (AppPKI, error)
    
    	// GetAppPrivkey returns the application private key (interface assumes attestation and identity have been verified already)
    	// The instance must be connected to through attested communication channels, whether directly or indirectly!
    	// This private key is also used for decrypting pre-encrypted secrets in configuration templates.
    	GetAppPrivkey(contractAddr ContractAddress) (AppPrivkey, error)
    
    	// SignCSR signs a certificate signing request (interface assumes attestation and identity have been verified already)
    	// The instance must be connected to through attested communication channels, whether directly or indirectly!
    	SignCSR(contractAddr ContractAddress, csr TLSCSR) (TLSCert, error)
    }
    
    ```
    
- Instance provisioning agent
    
    See https://pkg.go.dev/github.com/ruteri/tee-service-provisioning-backend/instanceutils/autoprovision
    
    ### Provisioning Process
    
    The tool follows a secure provisioning workflow:
    
    1. Initial Provisioning:
    
    - Generate TLS key pair and Certificate Signing Request (CSR)
    - Optionally wait for operator’s signature over TLS pubkey
    - Register with provisioning server through an attested channel
    - Derive disk encryption key from app’s private key (and the CSR)
    - Configure encrypted disk for re-provisioning
    - Write certificates, keys, and resolved configuration to encrypted disk
    
    2. Re-provisioning (after restart):
    
    - Read CSR from LUKS metadata
    - Re-register with provisioning server
    - Derive same disk encryption key
    - Mount existing encrypted volume
    - Verify cryptographic materials match
    - Update configuration with latest from server
    
    ### Operator Signature Flow
    
    When operator signature is enabled, the tool:
    
    - Calculates hash of the instance's public key
    - Exposes HTTP endpoints for operator interaction
    - Waits for a valid signature from an authorized operator
    - Embeds the signature as an extension in the CSR
    - Continues with registration once signature is received
    
    This approach provides additional security by ensuring that only
    instances approved by an operator can register with the system.
    
- Storage backends
    
    See https://pkg.go.dev/github.com/ruteri/tee-service-provisioning-backend/storage
    
    ```go
    type StorageBackend interface {
    	// Fetch retrieves data by its content identifier and type.
    	// Returns the data or an error if the content cannot be found or the backend is unavailable.
    	Fetch(ctx context.Context, id ContentID, contentType ContentType) ([]byte, error)
    }
    ```
    
    The storage offers a unified interface for storing and retrieving content identified by SHA-256 hash across multiple storage backends:
    
    - File system storage for local development and testing
    - S3-compatible storage for cloud deployments
    - IPFS storage for decentralized content
    - On-chain storage using Ethereum smart contracts
    - GitHub storage using repository content
    - Vault storage with TLS client certificate authentication
    
    ### Storage URI Format
    
    Storage backends are specified using URI format:
    
    ```
    [scheme]://[auth@]host[:port][/path][?params]
    ```
    
    Supported URI schemes:
    
    - file:///var/lib/registry/configs/
    - s3://bucket-name/prefix/?region=us-west-2
    - ipfs://ipfs.example.com:5001/
    - onchain://0x1234567890abcdef1234567890abcdef12345678
    - github://owner/repo
    - vault://vault.example.com:8200/secret/data
    
    ### Content Addressing
    
    Content is stored and retrieved using content addressing, where the content
    identifier is the SHA-256 hash of the data. Different content types (configs
    and secrets) are stored in separate namespaces.
    
    ### Types and Interfaces
    
    ContentID represents a unique identifier for any content in the system:
    
    ```go
    type ContentID [32]byte
    ```
    
    ContentType indicates what kind of content is being stored/retrieved:
    
    ```go
    type ContentType int
    
    const (
        ConfigType ContentType = iota
        SecretType
    )
    ```
    
    ### On-Chain Storage
    
    The OnchainBackend stores content directly in the Registry smart contract using:
    
    - mapping(bytes32 => bytes) configs - For configuration data
    - mapping(bytes32 => bytes) encryptedSecrets - For encrypted secrets
    
    URI format: onchain://<contract-address>
    
    ### GitHub Storage (Read-Only)
    
    The GitHubBackend fetches content directly from Git blobs in a GitHub repository:
    
    - Uses ContentID directly as a Git blob SHA
    - Directly accesses blob objects with no intermediate objects
    - Maximum simplicity with minimal API calls
    - Perfect integration with Git's object model
    
    URI format: github://owner/repo
    
    Note: if preferred this can be made to fetch from headless git rather than github.
    
    ### Vault Storage with TLS Authentication
    
    The VaultBackend retrieves content stored in HashiCorp Vault using TLS client certificate authentication:
    
    - Authentication: Uses TLS client certificates signed by the application CA from the KMS
    - Path Structure: Uses KV v2 secret engine with path format: {mount}/data/{path}/{type}/{content_id}
    - Content Types: Configs and secrets are stored in separate paths within Vault
    - Security: Strong authentication and encryption for sensitive data
    
    URI format: vault://vault.example.com:8200/secret/data
    
    The client certificate must be provided when creating this backend. It should be signed
    by the application CA configured in Vault for TLS authentication.
    
    Note that this is the only authenticated backend storage, and it’s ideal for storing secrets in a way that prevents them leaking even if KMS keys leak at a later point — since they can be simply deleted by the administrators. This does of course come with centralization.
    
- Operator configuration
    
    I assume that operator configuration does not have to be governed (probably a good assumption), so I would suggest that the operator simply posts their configuration post-boot to the instance. I provide a [simple implementation](https://github.com/ruteri/tee-service-provisioning-backend/blob/ff5dbbd3a839/instanceutils/operator-config-api/main.go) for this purpose.
    
    The operator’s configuration not following governance is separate from operator’s configuration not being transparent, and we can still achieve transparency by extending the instance’s measurement with values from the operator. The extensions would then be picked up by workload identity mapping, and hence would provide ways to ensure any predicate over operator-provided configuration.
    

**Not yet implemented**

- Governance and self-bootstrapping of the KMS
    
    With the currently implemented KMSes, there is no need for governance — since the admins define and control it. However, it would still be beneficial for transparency and ease of use (onchain CA and expected measurements).
    
    Note that the provisioner itself does not need governance, since it can be ran on the instance. Rather, it’s the KMS part of the integrated provisioner-kms service that needs governance.
    
    Governance should be an instance of an application governance contract more or less, but the (self-)bootstrap phase is a bit different, since KMS can’t assume another KMS exists.
    
- Ditching cvm reverse proxy
    
    There are only two interactions that require dynamically verified connections (client attestation when instance connects to provisioner or provisioner to KMS), and we can easily move those to an alternative attestation protocol.
    
    Simply extending the client certificate with an attestation will suffice. Instance should self-sign the extended certificate for full client-side attestation when requesting either the KMS or the remote provisioner.
    
- Transparency of measurements and identities
    
    Currently attestation reports are emitted as events, but there is no easy to access mapping of measurements, identities, and configurations. The attestation to identity mapping should come commented, for example with git commits.
    

**Future considerations**

- Governance actions
    
    One feature missing from BuilderNet’s builderhub and system-api is the ability to execute commands on an instance. For an onchain-governed decentralized service executing those commands will require whitelisting of at least the expected administrator and the command itself.
    
    Implementing this is not very difficult, and should be done separately as it’s only tangential to provisioning — by the fact that it also should be part of the application governance contract, and that the administrator must somehow be able to reach the instance. Ideally this is implemented as an integration of system-api with the new provisioning backend.
    
- Integrating with an industry-standard KMS
    
    Not many options that would fit the general use case, but for specific applications we could use any of cloud KMS, Lit Protocol’s KMS, or Dstack’s KMS, or maybe even just Vault.
    
- Global, privacy-preserving transparent and onchain-governed ingress
    
    Using onchain-governed PKI unlocks some interesting options for networking. One would be to implement a global ingress that is aware of the PKI and can be used to preserve privacy and route requests.
    

### **Integrations with our products**

- BoB benefits from provisioning as far as transparency and governance go: operator whitelisting, managing instances and authentication with CA. Because of the specifics of trust assumptions in BoB I would suggest to have the builder operate the KMS in a centralized way (KMS controls the CA), with the searcher relying on raw attestations rather than KMS for additional security guarantee (confidentiality from the builder and operator). Set up this way the integration is straightforward, and would give us all the sought benefits like integration of BoB with BNet and L2 sequencers while retaining all the guarantees, and not being any more complex wrt KMS.
- The provisioning system is mostly ready to PoC an L2 integration, with the necessity of multisig governance and MPC KMS operated by Flashbots and L2 operators (per operator). For governance we can use Safe multisig, and we should consider moving to an industry standard MPC KMS (but it’s not obvious if there’s any we’d like).
    - Because of the specific trust assumptions, L2 operators could run the KMS by themselves without changing any confidentiality guarantees.
- Integrating with BuilderNet can be done in multiple ways, with each having its own properties:
    1. Flashbots-only onchain governance, which gives us sought for transparency but no additional trust benefits.
    2. Flashbots-operated KMS, which is very much the state right now but in addition would provide onchain PKI for a much improved UX.
    3. MPC KMS operated by Flashbots and some or all of the operators, which improves trust guarantees (as long as governance is also multisig)
    4. Multisig governance with something like Safe that would be beneficial to both transparency and reducing trust assumptions (as long as KMS is also MPC-based)
    
    I would suggest to PoC (1) and (2) straight away for the improved UX and transparency, since they are not any more complex than what we are doing right now. Provisioning backend+SimpleKMS replaces the BuilderHub, and we are mostly done.
    
    Note that with (1) and (2), the onchain PKI is fully operational and can be used to greatly improve cross-TEE-application communication, like BoB <> BNet or BNet <> L2.
    
    With (1) and (2) done, (3) and (4) **do not change any of the APIs or instance behaviors**. So moving to (3) and (4) can be done separately at any point and would result in a massive reduction to trust assumptions, effectively removing any remaining trust in Flashbots as far as the instances themselves are concerned.
    
- Note that provisioning is ready to be integrated with Dstack as is.

# Design analysis

**Performance**

Provisioning is all in the cold path, with only regular TLS handshakes happening for communication. Hence, no impact on performance in cross-instance communication, or cross-application communication, or in end user communication.

**Operational complexity**

This proposed solution contains a mix of purpose-built components and standard industry ones.

1. Regular DNS and industry-standard *public* storage decrease at least some of the complexity as compared to builderhub or any of the previous proposals.
2. Use of onchain governance does introduce some friction. However, because the interface is simple and unassuming, any standard industry wallet will work just fine. This should keep the added complexity manageable if compared to alternatives (like a built-in multisig).
3. Instance provisioning agent is about as complex as the current BuilderNet’s one, however it is a single piece rather than multiple scripts and should help with managing complexity.
4. Relying on regular TLS PKI rather than CVM proxy should **greatly** reduce operational complexity for clients as well as developers.
    1. What’s more, the provisioning system as is does not need to rely on cvm proxy at all, which would further reduce development overhead.
5. Operating MPC KMS should not be a huge hassle, however because the current implementation is purpose-built it will add operational and development overhead.

**Security**

There are a couple of security-critical components as well as security-critical routines and channels. Compromising any of the components, routines, or channels **will result in compromise of downstream applications**.

1. Compromise of KMS, whether through a bug or out-of-band collusion results in the compromise of *all* applications using that KMS.
    
    Mitigations:
    
    1. Move to industry standard MPC KMS implementation
    2. Make sure the admin set is not incentivized to collude
        1. If that’s not possible, use a TEE KMS like Dstack’s KMS. This negatively impacts liveness, but circumvents collusion issues.
2. Compromise of a provisioning instance might result in:
    1. Compromise of all applications which use KMSes whitelisting that provisioning instance (in the worst case scenario of full access to the provisioning instance)
    2. Compromise of all applications which request registration after an attacker gains access to unencrypted network data (in the scenario of read access to the instance)
    
    Mitigations:
    
    1. Security hardening of the instances — sandboxing of processes in particular to avoid worst case scenario
    2. Use encryption in flight even over [localhost](http://localhost)
3. Compromise of governance contract, or of the governance chain’s network results in compromise of everything through mimicking governance actions.
    
    Mitigations:
    
    1. Use factually decentralized, difficult to eclipse blockchains 
    2. Ensure censorship resistance in the KMS (TODO!)
    3. Carefully whitelist KMS operators
4. Use of a malicious blockchain RPC results in man-in-the-middle and various impersonation attacks that will leak all confidential data
    
    Mitigations:
    
    1. Use hardcoded CACertificates where possible instead of relying on chain RPC. The yearly or so refresh of CA is not a big enough impact compared to issues with using RPCs or light clients
    2. Use local light clients over RPCs even for non-production workloads
    3. Only use full, validating nodes for production workloads
        1. Note that this is the reason I believe provisioning API should be integrated with the KMS rather than with the instance: because both provisioning and KMS require a full node for security.
5. Compromise of an instance results in unauthorized ability to pose as an instance of the application, or to execute a man-in-the-middle attack, and to read all the configuration secrets.
    
    Mitigations:
    
    1. Ensure secrets do not hold a lot of funds
    2. Store critical secrets in Vault rather than a public storage backend so that it can be taken down and future compromise will not endanger it
    3. Rotate secrets periodically if possible
6. Improper validation of attestations results in compromise of all components.
    
    Mitigations:
    
    1. Possibly move away from cvm-reverse-proxy in favor of in-house aTLS
    2. Simplify and audit attested channels

# System maintenance

1. KMS will require regular security upgrades. Depending on the type of KMS that might mean re-bootstrapping all instances in the worst case, or a governance action (whitelisting a new measurement) in the best case.
2. Provisioning API will require regular security upgrades as well as new features. If the provisioning API is integrated with KMS and running remotely, the upgrade will require applications to adjust expected measurements — either through an upgrade of the image or a governance action.
    1. Note that provisioning API uses KMS for deriving cryptographic keys, and is itself fully stateless.
    
    If provisioning API runs on the instance, it does not need any additional upgrade process — rather it’s the KMS itself that requires governance over expected measurements.
    
3. Governance contracts might require upgrades, in which case either a proxy pattern should be employed, or the application images should simply be configured to use a different address. If that’d be the case, all the clients must move along to the new address as well — unless it’s fetched from something like ENS.
4. Storage backends and DNS do not need any special maintenance processes.

Note: the PKI is currently not rotating. Certificates should be re-signed every day or so, but they are quite simple to rotate as nothing actually depends on them. However, rotating the onchain CACert will require all clients to upgrade their CA and should not be done too frequently.

# Design validation

Unclear how to validate the design other than to review the PoC implementation and try to integrate at least two of BuilderNet, BoB and L2 BB.

The PoC implementation you can find at https://github.com/Ruteri/tee-service-provisioning-backend.