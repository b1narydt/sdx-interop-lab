<!-- tpnil:provenance-header -->
**TPNIL pinned source text.** SDX Protocol specification v0.1, dated 2026-07-17, revised 2026-09-01; keys, envelope and anchoring ratified 2026-09-01. This file holds the page *Keys, identity and delegation*, a normative section ratified on 2026-09-01. Requirement citations use the clause prefix `KEYS`.

- Source page: <https://sdxprotocol.org/protocols/data-sharing/v0.1/keys/>
- Retrieved from: <https://sdxprotocol.org/llms.mdx/protocols/data-sharing/v0.1/keys.md>, the site's Markdown rendition of the source page
- Retrieved at: 2026-11-11T05:08:31Z
- SHA-256 of the retrieved bytes: `e4315e4eaadcab3b4bb3c229b2d98314b5e70ea7f10310f7846589f4a0f4f79f`
- Licence: SDX specification texts and test vectors licence, Version 1.0, 1 September 2026, Licensor mintBlue B.V. [Reference copy](../../../../../LICENSES/SDX-Specification-License-1.0.reference.txt)
- Modification: none. The retrieved bytes follow the closing marker of this header unchanged; TPNIL added only this header. Root-relative links in the text resolve against `https://sdxprotocol.org`.

Attribution: SDX Protocol specification, version 0.1 (2026-07-17, revised 2026-09-01). The source page is the canonical publication. This copy retains the SDX licence terms and is excluded from TPNIL's Apache-2.0 grant; see the [third-party notices](../../../../../THIRD_PARTY_NOTICES.md).
<!-- tpnil:upstream-text-follows -->
# Keys, identity and delegation (/protocols/data-sharing/v0.1/keys)



> Normative. Reflects the specification as ratified on 1 September 2026. Version pinning is by date. Where this text and a published test vector disagree, the vector wins and the text is corrected.

## 1. Keys and derivation [#1-keys-and-derivation]

### 1.1 Scope and roles [#11-scope-and-roles]

This section specifies how an SDX runtime derives every key it uses: the root keying material it starts from, the two elliptic curves it runs in parallel, the namespaced key paths that address individual keys, the wire form of the derivation identifier that both sides of an interop pair must compose identically, and the epoch semantics that let a runtime rotate its root key without losing the ability to replay its own history.

Two roles appear throughout. A **writer** constructs an Action, encrypts its fields, signs the envelope and submits it. A **reader** receives an admitted Action, verifies it, decrypts what it is entitled to read and dispatches it. Both roles derive keys from the same grammar, which is what makes replay deterministic: a reader re-derives exactly the keys the writer used, from the same inputs, years later.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119.

### 1.2 Terminology [#12-terminology]

**Root keying material (IKM).** The 64-byte (512-bit) secret at the top of a runtime's key tree. Everything below it derives one way; no derived key can be used to climb back up.

**Per-curve seed.** A 32-byte (256-bit) curve-specific root, produced by expanding the root keying material with a curve-specific label (§1.4).

**Derivation namespace.** A short lowercase string that separates one key universe from another, for example signing keys from encryption keys. Called a protocol identifier in the underlying key-derivation standard.

**Key path.** The hierarchical identifier of an individual key within a namespace, for example `account/<accountId>/runtime/<runtimeId>/action/<actionId>/field/<fieldName>`. Called a key identifier in the underlying key-derivation standard.

**Derivation identifier.** The single string `<securityLevel>-<namespace>-<keyPath>` that is hashed during derivation. It is a wire and interop artefact: two parties deriving a shared key MUST compose byte-identical derivation identifiers or they will derive different keys.

**Counterparty.** A parameter of the derivation function; either `'self'`, `'anyone'`, or a specific public key. For a runtime's internal derivations, `'self'` is canonical.

**Epoch.** A monotonic integer (0, 1, 2, ...) naming a generation of the runtime's root keying material. Epoch 0 is genesis.

**Public audit layer.** The append-only public substrate on which Actions are anchored. This specification treats it as an immutable, world-visible log: anything written to it is permanent.

### 1.3 The open derivation standard this profile builds on [#13-the-open-derivation-standard-this-profile-builds-on]

Key derivation uses an open, published key-derivation standard whose algorithm is summarised in §1.8. The standard is defined over secp256k1; §1.8 defines its application to P-256, which is otherwise identical apart from the curve parameters. Implementations MUST NOT substitute a different derivation algorithm, because the standard's counterparty symmetry (both parties independently derive the same child key from opposite sides of a shared secret) is load-bearing for delegation and for cross-party locks.

Two grammar rules of that standard are carried into this profile and are normative here:

* A namespace is **space-form**: lowercase letters, digits and spaces only; 5 to 280 characters; no consecutive spaces; and it MUST NOT end with the word `protocol`.
* A key path is an opaque string of 1 to 1033 bytes within its namespace. This profile uses structured key paths with `/` separators (§1.6).

#### 1.3.1 The derivation profile (normative) [#131-the-derivation-profile-normative]

The concrete strings that enter a derivation are **deployment parameters**, not values fixed by this specification. Together they form a deployment's **derivation profile**:

1. the **derivation namespace strings** (§1.7);
2. the **per-curve derivation labels** used to expand the root keying material (§1.4.2);
3. the **key-path segment vocabulary**: the literal keyword segments at each level and the registered level-4 purposes (§1.6);
4. the **mandate credential type identifier** (§2.11).

Normative rules:

* A deployment MUST fix its derivation profile before first use and MUST publish it to its consortium.
* Every party to a deployment MUST use that profile's strings byte for byte. Two parties deriving a shared key compose the same derivation identifier or they derive different keys, so a profile disagreement is not a cosmetic difference; it is a silent interoperability failure.
* A deployment MUST NOT change a profile value once records exist under it. Records are verifiable only under the profile they were created under: the namespace and key-path strings are inputs to the derivation itself, the per-curve labels sit at the root of both key trees, and the credential type identifier is covered by the credential's signature and by the digest anchored with the grant.
* A profile value MUST satisfy the grammar and length rules of §1.3 and §1.6, which are normative regardless of the values chosen.

**The concrete strings in this document form an example profile and are not normative.** They appear so that the grammar, the worked derivations and the conformance vectors are readable end to end. Tables that carry them are labelled as example values. An implementation reading this document takes the shapes, the rules and the byte lengths as binding, and takes the strings from its own deployment's published profile.

### 1.4 Root keying material and the per-curve split [#14-root-keying-material-and-the-per-curve-split]

#### 1.4.1 Root keying material [#141-root-keying-material]

A runtime's root keying material MUST be exactly 64 bytes. Implementations MAY source it from a mnemonic-derived seed, from a passphrase stretched with PBKDF2, or from a hardware or cloud key service that holds the material and performs derivation internally (§1.4.4).

For browser-resident clients the passphrase profile is PBKDF2-HMAC-SHA-256 with 200,000 iterations and a 512-bit output. Implementations SHOULD perform this through the platform's native cryptography API rather than in interpreted code.

#### 1.4.2 The split (normative) [#142-the-split-normative]

The two curve trees MUST be seeded from the root keying material via HKDF-SHA-256 (RFC 5869) with these parameters. The `info` labels are profile values (§1.3.1); the ones shown are the example profile's. Everything else here is normative.

```
secp256k1_seed = HKDF-SHA-256(
  ikm   = ikm_512,          -- the full 64 bytes
  salt  = "",               -- empty
  info  = "sdx-secp256k1",  -- EXAMPLE profile label; ASCII bytes of the literal
  L     = 32
)

p256_seed = HKDF-SHA-256(
  ikm   = ikm_512,
  salt  = "",
  info  = "sdx-p256",       -- EXAMPLE profile label; ASCII bytes of the literal
  L     = 32
)
```

Rules:

* Both seeds MUST be derived from the **full 64 bytes**. An implementation that truncates the root keying material to 32 bytes before the extract step silently halves its entropy and will fail the test vectors of §1.12.
* The extract step is HMAC-SHA-256 with an empty salt, producing a 32-byte pseudorandom key. The expand step produces exactly one output block, since L is 32.
* The `info` strings are **hyphenated ASCII labels**, not namespaces. They are consumed by HKDF, which imposes no grammar on them. Implementations MUST NOT rewrite them into the space-form of §1.3; doing so produces a different and undefined key tree.
* The two labels MUST come from the deployment's published profile (§1.3.1) and MUST be used byte for byte. They are the highest-leverage values in the profile: they sit at the root of both trees, so a single edited character re-derives every key the deployment has ever produced.
* The two labels MUST differ from each other. A profile that gives both curves the same label defeats the separation the split exists for.
* The `info` strings MUST be defined once in a single constant and referenced from there. A duplicated inline literal is the classic way for the two to drift apart silently.

Any change to either `info` string, to the salt, to the digest, or to the output length re-derives the entire tree beneath it. For the secp256k1 tree that makes every previously encrypted field undecryptable; for the P-256 tree it changes the runtime's published identity, which every party that pinned it observes as an unannounced rotation. Such a change is legitimate only through the rotation protocol of §1.10.

#### 1.4.3 Seed validity (normative) [#143-seed-validity-normative]

* `secp256k1_seed`, interpreted as a big-endian integer, MUST lie in `[1, N_secp256k1 - 1]`.
* `p256_seed`, interpreted as a big-endian integer, MUST lie in `[1, N_p256 - 1]`.

where

```
N_secp256k1 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
N_p256      = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
```

On the astronomically unlikely failure of either check, the implementation MUST abort and report the root keying material as unusable rather than clamping the value into range. Clamping is deterministic but diverges from any other conforming implementation, which breaks interop precisely where it is hardest to detect.

The validity check MUST be applied to both seeds before either is returned. A correct validator that is never called is the failure mode this rule exists to close.

#### 1.4.4 Enclave and signer deployments [#144-enclave-and-signer-deployments]

Where the root keying material lives in a hardware security module, an enclave or a cloud key service, the per-curve split does not happen in the runtime's process. Such a deployment either holds the full root keying material and performs the split and the curve-scoped derivation internally on each call, or holds two pre-split per-curve seeds as independent managed keys with matching label semantics. The runtime then asks for operations by curve label, for example `sign(curve, data, ...)` and `derive(curve, namespace, keyPath, counterparty)` with `curve` in `{'secp256k1', 'p256'}`.

An enclave implementation MUST produce bit-identical results to §1.4.2 for the same root keying material. This is verifiable against the test vectors of §1.12 without exposing the material itself.

### 1.5 The two curves [#15-the-two-curves]

A runtime runs two parallel key trees, seeded independently per §1.4.2.

| Concern                                        | Curve            | Why                                                                             |
| ---------------------------------------------- | ---------------- | ------------------------------------------------------------------------------- |
| Signing transactions on the public audit layer | secp256k1        | Required by the audit layer's consensus rules                                   |
| Counterparty-derived field keys and ECDH       | secp256k1        | Native to the derivation standard's reference implementations                   |
| Envelope payload signatures                    | P-256            | ES256, the canonical JOSE signing algorithm                                     |
| Credential and token interoperability          | P-256            | Required for `alg: ES256` in JOSE, SD-JWT and W3C Verifiable Credential tooling |
| Keys held in a hardware security module        | P-256            | Broadly supported in hardware; secp256k1 much less so                           |
| Qualified electronic signatures under eIDAS    | P-256 (or P-384) | secp256k1 requires special attestation under eIDAS                              |

Normatively:

* Envelope payload signatures MUST use P-256 with ES256.
* Signatures over transactions on the public audit layer MUST use secp256k1.
* Field-level symmetric encryption keys are derived on the secp256k1 tree.
* Per-recipient key identifiers for the envelope's outer and per-field encryption layers are derived on the P-256 tree, so that they are curve-consistent with the signing key identifiers of the same Action. See the envelope section for the recipient-identifier recipe itself.

A single Action therefore typically produces derivations on both trees: symmetric field keys and the audit-layer transaction signature on secp256k1, and the envelope payload signature plus recipient key identifiers on P-256.

Breaking one curve does not compromise the other. The private roots are distinct (different HKDF labels), the derivation arithmetic runs in different groups, and no secret crosses between the trees. An attacker needs both curves, or the root keying material itself, to hold all of a runtime's signing powers.

### 1.6 Key path grammar (normative) [#16-key-path-grammar-normative]

#### 1.6.1 Five levels [#161-five-levels]

Shown with the example profile's segment vocabulary (§1.3.1):

```
level 0  root keying material  not directly addressable
level 1  account               account/<accountId>
level 2  runtime               account/<accountId>/runtime/<runtimeId>
level 3  action                account/<accountId>/runtime/<runtimeId>/action/<actionId>
level 4  action sub-resource   account/<accountId>/runtime/<runtimeId>/action/<actionId>/<purpose>/<id>
```

The **structure** is normative: five levels, this nesting, one keyword segment naming each level followed by that level's identifier, `/` as the separator. The **keyword words themselves** are profile values, so a deployment whose profile spells the level-2 keyword differently is conforming as long as it spells it that way everywhere. The angle-bracketed components are placeholders for values, never literals.

Shorter prefixes are valid key paths for higher-level derivations. A reader verifying an encrypted field derives at level 4 with the full path; a producer of an account-scoped signing key derives at level 1.

Level 4 keys a resource scoped to a single Action. `<purpose>` MUST be one of a **closed** set registered in the deployment's profile. A `<purpose>` the validator does not recognise MUST be rejected at the derivation boundary rather than passed through. The example profile registers three, and a deployment that adds a fourth registers it in its own profile with the same discipline:

| `<purpose>` (example profile) | `<id>`        | Used for                                                                         |
| ----------------------------- | ------------- | -------------------------------------------------------------------------------- |
| `field`                       | `<fieldName>` | Per-field envelope encryption                                                    |
| `handoff`                     | `<refIdHex>`  | Cross-domain handoff output lock, addressed to a named recipient                 |
| `topup`                       | `<n>`         | Funding top-up output lock; `<n>` is the output ordinal, `0` for a single output |

New purposes are added only by amendment to the profile, never ad hoc. Both the deriving side and the validating side MUST generate their accepted set from one shared constant, so that a purpose added on one side and not the other fails loudly.

One level-3 keyword variant exists alongside `action`:

```
level 3  session   account/<accountId>/runtime/<runtimeId>/session/<sessionId>
```

used by ephemeral session actors (§2.14). `session` is a level-3 keyword, not a level-4 purpose, so the closed set above is unaffected. A conforming key-path validator MUST accept `account/<accountId>/runtime/<runtimeId>/session/<sessionId>`.

A further level-3 variant addresses delegation actor keys:

```
level 3  delegation  account/<accountId>/runtime/<runtimeId>/delegation/<delId>/actor/<actorPubKey>
```

See §2.14 for its status: it is retained for counterparty-symmetric flows and is not on the dispatch-time verification path, which is pubkey-pinned.

#### 1.6.2 Identifier formats (normative) [#162-identifier-formats-normative]

| Component     | Format                                                        | Visible on the public audit layer       | Notes                                                                              |
| ------------- | ------------------------------------------------------------- | --------------------------------------- | ---------------------------------------------------------------------------------- |
| `accountId`   | base58check of 128 bits of CSPRNG output                      | No                                      | Opaque. Issued when the account is created; held in the derivation registry (§1.9) |
| `runtimeId`   | base58check of 128 bits of CSPRNG output                      | No                                      | Opaque. Issued when the runtime is created                                         |
| `actionId`    | ULID: 26 Crockford base32 characters, 128 bits, time-sortable | Carried in the envelope header in clear | Producer-assigned at Action construction, before signing (§1.6.3)                  |
| `fieldName`   | UTF-8, 1 to 256 bytes, NFC-normalised                         | No; lives inside the envelope payload   | Application-defined; SHOULD be stable across an Action schema's lifetime           |
| `refIdHex`    | lowercase hexadecimal                                         | No                                      | Identifies a handoff output                                                        |
| `<n>` (topup) | decimal integer                                               | No                                      | Output ordinal                                                                     |

Rules:

* `accountId` and `runtimeId` MUST be opaque random values. They MUST NOT be derived from a public key or from any value visible on the public audit layer. A runtime's public key is visible in its output locks; deriving the runtime identifier from it would let anyone holding the root keying material enumerate the whole tree without further information, which is exactly what the derivation registry (§1.9) exists to prevent.
* `fieldName` MUST be NFC-normalised before it enters a key path. Two visually identical field names in different normalisation forms derive different keys, and the failure surfaces much later as an undecryptable field.
* The separator `/` MUST NOT appear inside an individual component. A producer MUST reject a field name containing `/` at Action-construction time rather than escaping it.

#### 1.6.3 The action identifier is not the transaction identifier (normative) [#163-the-action-identifier-is-not-the-transaction-identifier-normative]

`actionId` MUST be assigned by the producer at Action construction, before any encryption or signing, and MUST NOT be the identifier of the anchoring transaction.

The reason is a circular dependency. A transaction identifier is the hash of the signed transaction; the signed transaction contains the envelope; the envelope contains per-field ciphertexts; those ciphertexts are encrypted under keys whose derivation identifier names the Action. If the Action were named by the transaction identifier, the producer would need a value that cannot exist until after the work that depends on it is complete.

ULID is the recommended format: short, time-sortable within a millisecond, and widely implemented, which helps a reader's reordering behaviour. Implementations MAY substitute UUIDv7 or a deterministic canonical hash over the Action's contents, provided collision resistance holds across the runtime's whole lifetime.

The consequence for the Action's shape is that two identifiers coexist and are not interchangeable. The `actionId` is producer-assigned, used in every derivation path, and carried in the envelope header in clear. The transaction identifier is assigned after signing, used by the audit layer for walking the runtime's output chain and for sequencing, and never used in derivation. A reader therefore decrypts an Action's fields without knowing anything about the transaction that carried it, which keeps decryption independent of audit-layer concerns such as a reorganisation partway through a replay.

### 1.7 Derivation namespaces (normative) [#17-derivation-namespaces-normative]

Namespaces MUST be used at security level 2, the counterparty-specific level.

A deployment's profile (§1.3.1) MUST register one namespace for each of the six roles below. The **roles** are normative: every deployment separates these six key universes, and the separation is what stops a key derived for one purpose being usable for another. The **strings** are profile values, and the ones in this table are the example profile's.

| Namespace (example profile) | Role                     | Curve               | Purpose                                                                                                                                                                                                                                            |
| --------------------------- | ------------------------ | ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `sdx encrypt`               | encryption               | secp256k1 and P-256 | On secp256k1: symmetric field-encryption keys (AES-256-GCM keys obtained through the standard's symmetric derivation). On P-256: per-Action public keys used as recipient key identifiers for the envelope's outer and per-field encryption layers |
| `sdx sign`                  | signing                  | secp256k1 and P-256 | Per-Action signing keys. On secp256k1: transaction signing and output locks on the public audit layer. On P-256: envelope payload signatures with ES256                                                                                            |
| `sdx delegate`              | delegation               | either, per grant   | Delegation actor keys, and ephemeral session self-derivation under the `session` key-path variant                                                                                                                                                  |
| `sdx transport auth`        | transport authentication | secp256k1           | Identity keys for the transport's mutual-authentication handshake                                                                                                                                                                                  |
| `sdx rotation`              | rotation                 | secp256k1 and P-256 | Reserved for rotation-Action signing keys during a dual-root transition. A deployment whose rotation envelopes sign under the signing namespace reserves this role without deriving under it, which the last rule below permits                    |
| `sdx handoff`               | handoff                  | secp256k1           | Cross-domain handoff outputs. The producing runtime locks the output under this namespace with `counterparty` set to the recipient's public key, so that by the derivation standard's symmetry only the addressed recipient can spend it           |

Rules:

* Implementations MUST NOT derive under a namespace absent from their deployment's profile. Adding a role is an amendment to the profile, published like any other part of it, because a namespace is what separates one key universe from another and an unregistered one is invisible to every other party.
* The six namespaces of a profile MUST be distinct from one another.
* The signing and encryption namespaces are **curve-parametric**: one string per role, invoked on both curve derivers under the respective per-curve seeds. The curve is determined by which deriver consumes the string, not by the string itself, so a profile MUST NOT register separate per-curve spellings for these two roles.
* Namespaces are space-form per §1.3. Hyphens appear only in the HKDF labels of §1.4.2, which are a different kind of string at a different layer. Implementations MUST NOT substitute hyphens for spaces here.
* An implementation MUST NOT derive a key under one namespace and use it for the purpose of another. The derivation function does not enforce this; the separation exists precisely so that a signing key can never be substituted for an encryption key, and it holds only if implementations respect it.
* A profile MAY reserve namespaces it does not yet derive under; verifiers bind to the namespace actually used for signing.

### 1.8 Deriving a key [#18-deriving-a-key]

#### 1.8.1 The derivation identifier [#181-the-derivation-identifier]

The wire form is:

```
derivation_identifier = "<securityLevel>-<namespace>-<keyPath>"
```

Separators are literal hyphens. The namespace segment contains spaces; the key path segment contains `/` and, at level 4 with the field purpose, an application-supplied field name. A worked example, under the example profile:

```
2-sdx encrypt-account/3MNQpxFAsp/runtime/8kRt2wVbZq/action/01JB8ZK3QN7T4YVX2C9M5RDPWA/field/photoHash
```

Length budget: with a 26-character action identifier, roughly 20-character account and runtime identifiers, and a 256-byte maximum field name, the worst-case key path is about 400 characters and the derivation identifier about 450, comfortably inside the 1033-byte key-path limit of §1.3.

#### 1.8.2 The algorithm [#182-the-algorithm]

For a party S deriving a child key of party R:

```
shared_secret_point = S.private x R.public              -- ECDH on the curve in use
hmac_key            = SEC1-compressed(shared_secret_point)   -- 33 bytes, 0x02||X or 0x03||X
hmac                = HMAC-SHA-256(key = hmac_key, message = utf8(derivation_identifier))
scalar              = int(hmac, big-endian) mod N
```

then

```
child_public  = (scalar x G) + R.master_public
child_private = (scalar + R.master_private) mod N
```

where `G` and `N` are the generator and order of the curve in use. On P-256 these are the values of §1.4.3 and the standard P-256 generator; the arithmetic is otherwise unchanged from the secp256k1 definition.

**Scalar rejection.** If `scalar` is `0` or is greater than or equal to `N`, the derivation MUST fail. Callers MAY retry with a different derivation identifier or abort. The probability is approximately 2^-256; the rule exists so that no implementation quietly produces a degenerate key.

**Self-derivation.** When `counterparty` is `'self'`, the ECDH collapses to `self.private x self.public`. Implementations SHOULD compute the shared point directly from the stored key rather than performing two scalar multiplications. The result is unchanged: deterministic, self-paired and canonical.

**Symmetric keys.** A symmetric key is derived by the same procedure with the resulting shared material used as a 32-byte AES-256-GCM key. Field encryption uses AES-256-GCM.

#### 1.8.3 Signature format [#183-signature-format]

For interoperability with JOSE, SD-JWT and eIDAS tooling:

* P-256 signatures MUST be produced in IEEE P1363 form, that is `r || s`, 32 bytes each, 64 bytes total. This is the JOSE `ES256` encoding.
* Verifiers MUST accept P1363 form and MAY additionally accept DER for robustness. A verifier that rejects by length MUST reject anything that is not 64 bytes, which excludes the 70 to 72 byte DER encodings.
* The payload is hashed with SHA-256 as part of signing. Callers pass the raw payload bytes, not a digest.

ECDSA is malleable on both curves: `(r, s)` and `(r, N - s)` are both valid. Implementations SHOULD canonicalise to the low-`s` form when producing signatures and SHOULD accept either form when verifying. ES256 does not require low-`s`, so a verifier that rejects high-`s` will reject signatures from conforming general-purpose JOSE libraries.

#### 1.8.4 Worked derivations [#184-worked-derivations]

All four examples below use the example profile's strings (§1.3.1); substitute your deployment's.

Symmetric field key:

```
key = deriveSymmetricKey(
  [2, 'sdx encrypt'],
  `account/${accountId}/runtime/${runtimeId}/action/${actionId}/field/${fieldName}`,
  'self'
)
```

Envelope payload signature (P-256, ES256):

```
sig = p256.sign(
  payloadBytes,
  [2, 'sdx sign'],
  `account/${accountId}/runtime/${runtimeId}/action/${actionId}`,
  'self'
)
```

Audit-layer transaction signature (secp256k1):

```
sig = secp256k1.sign(
  data,
  [2, 'sdx sign'],
  `account/${accountId}/runtime/${runtimeId}/action/${actionId}`,
  'self'
)
```

Counterparty-symmetric delegation key, derived independently by both sides to the same value:

```
// runtime side: counterparty is the actor's public key
runtimeSide = derivePrivateKey([2, 'sdx delegate'], path, actorPubKey)

// actor side: counterparty is the runtime's identity public key
actorSide   = derivePrivateKey([2, 'sdx delegate'], path, runtimeIdentityPubKey)

// runtimeSide == actorSide
```

### 1.9 The derivation registry [#19-the-derivation-registry]

#### 1.9.1 Purpose [#191-purpose]

A runtime SHOULD maintain a local registry mapping each issued derivation identifier to its semantic meaning and issuing context. The registry serves three purposes:

1. **Defence in depth against root compromise.** Deriving a key requires the full derivation identifier. An attacker who obtains the root keying material but not the registry must guess the account identifier, the runtime identifier and the field name, none of which appear on the public audit layer. This does not make root compromise survivable, but it bounds what a single compromise yields.
2. **Forensic reconstruction.** Answering "which fields did this runtime ever derive keys for" without decrypting every envelope.
3. **Rotation auditing.** Every row is tagged with the epoch that issued it.

The registry is encrypted at rest under a **registry key** that MUST be held in a different trust domain from the root keying material. Suitable sources, in rough order of preference by deployment profile, are an operating-system keychain (developer and self-hosted), a TPM-sealed blob (server with a TPM), a hardware security module or cloud key service reached through a different identity principal from the one that reaches the root keying material (enterprise), an explicit environment variable (test and CI only), and a second secret-sharing custody instance with different shareholders from the root's (consortium). The registry key is loaded once at boot and held in protected memory for the process lifetime.

#### 1.9.2 Row contents [#192-row-contents]

Each row records: the derivation identifier, its namespace, its key path, its level (1 to 4), the epoch at derivation time, the production timestamp in milliseconds, the action identifier where one applies (null for higher-level derivations), and an optional operator-readable label. The label is convenience only and MUST NOT be load-bearing for any decision.

Rows MUST be written in the same transaction as the Action they belong to, and MUST roll back with it. A registry that has drifted out of step with the action log is worse than no registry, because it is trusted.

#### 1.9.3 At-rest encryption [#193-at-rest-encryption]

Where rows are encrypted individually rather than through whole-store encryption, the following applies. The cleartext columns are the ones needed to select a row without decrypting it: a hash of the derivation identifier as primary key, a hash of the runtime identifier, the epoch, the action identifier, and the production timestamp. The ciphertext and its initialisation vector are separate columns. The encrypted record carries the derivation identifier, namespace, key path, level, runtime identifier and label in clear inside the ciphertext.

The AES-256-GCM additional authenticated data MUST cover the cleartext selector columns, serialised deterministically. Without this, an attacker who can write to the store can move a valid ciphertext under a different selector and the authentication tag will still verify, which turns a read-only compromise into a substitution attack.

A registry key of the wrong length MUST be rejected when it is loaded, not when it is first used. Tampered ciphertext MUST fail at decryption with a distinct, typed error.

#### 1.9.4 Rebuilding after registry-key loss [#194-rebuilding-after-registry-key-loss]

If the registry key is lost but the root keying material survives, the registry is recoverable:

1. Halt the runtime.
2. For each Action in the window, decrypt the envelope using the root material for that Action's epoch, extract the field descriptors, and re-derive the derivation identifiers under the grammar of §1.6.
3. Insert the rebuilt rows, using each Action's own declared time as the production timestamp.
4. Provision a new registry key and encrypt the rebuilt registry under it.

This is linear in the number of Actions and proportional to decryption cost; expect hours for a runtime with years of history. It is a recovery procedure, not a routine one.

If **both** the root keying material and the registry key are lost, historical decryption is gone. No protocol mechanism recovers it. The archive of past root material is the runtime's durability, and this is the single most important operational invariant in this specification.

### 1.10 Epochs and rotation [#110-epochs-and-rotation]

#### 1.10.1 Model [#1101-model]

Rotation is an event on the public audit layer, not a configuration change. Each runtime maintains a monotonic `keyEpoch` starting at 0. Every Action carries the epoch under which it was encrypted, in its envelope header. A runtime maintains a local **keyring** mapping each epoch to the configuration of the root material that served it, retained indefinitely.

Rotation is for root-key transitions: suspected compromise, scheduled hygiene, departure of a custodian, or deprecation of an algorithm. It is not the mechanism for routine key change (every Action already derives fresh keys) nor for changing who may act (that is revocation and re-granting, §2.6).

#### 1.10.2 The rotation Action (normative) [#1102-the-rotation-action-normative]

A rotation is announced by a reserved system Action `_rotation`, whose arguments are:

```
{
  oldEpoch:                     <uint>,
  newEpoch:                     <uint>,
  newIdentityPubKey_secp256k1:  <33 bytes, SEC1-compressed>,
  newIdentityPubKey_p256:       <33 bytes, SEC1-compressed>,
  reason:                       'scheduled' | 'compromise' | 'personnel' | 'crypto-deprecation' | <string>,
  effectiveAt:                  <uint>    -- milliseconds since the Unix epoch
}
```

The Action's own envelope carries `keyEpoch = oldEpoch`, because it is the last Action encrypted under the outgoing root.

`_rotation` is a reserved method name. Application code MUST NOT declare it.

**Dual signature.** The rotation envelope's payload signature MUST be the concatenation of two ES256 signatures, `oldRootSig || newRootSig`, and the envelope header MUST carry `dualSigned: true` so that a reader knows to verify both. A single-signed rotation Action MUST be rejected.

The conjunction is what makes the transition safe. The old root alone could announce a transition to a key an attacker controls; the new root alone has no provenance. Together they bind intent (the outgoing root authorises this transition) to effective control (the incoming root demonstrably holds the new identity).

**Procedure.** The runtime MUST be paused to new writes before the transition begins: the dispatch queue drained, write endpoints returning a retryable failure. Reads continue to serve current state. The operator MUST hold the old root (to sign) and the provisioned new root (to sign and to derive the new identity keys), and SHOULD require a second operator's sign-off. Then:

1. Provision the new root. It MAY be of a different kind from the old one; a transition from a mnemonic-backed root to a key-service-backed root, or a change of secret-sharing threshold, is an ordinary rotation.
2. Derive the new identity public keys on both curves.
3. Construct the rotation Action.
4. Sign it with both roots.
5. Construct the anchoring transaction. Its first input spends the runtime's current tip output, unlocked by the old identity; its first output is locked by the **new** identity. This is the point at which control of the runtime's output chain transfers.
6. Submit. The admitting network verifies both signatures and confirms that the input spends the current tip.
7. Await confirmation.
8. Record the new epoch in the keyring as active and mark the previous one archived.
9. Archive the old root material in cold storage. **The old root MUST NOT be destroyed**; historical replay requires it.
10. Resume writes. New Actions carry the new epoch.

#### 1.10.3 Verifying a rotation on replay [#1103-verifying-a-rotation-on-replay]

A reader that encounters a rotation Action MUST:

1. Detect the reserved method `_rotation`.
2. Verify that `dualSigned` is set; reject if not.
3. Verify `oldRootSig` under the identity recorded in the keyring for `oldEpoch`.
4. Verify `newRootSig` under the identity declared in `newIdentityPubKey_p256`.
5. Bind both signatures to the Action. The JOSE `kid` of each payload signature MUST be the SEC1-compressed hexadecimal of the per-Action signing public key derived under `[2, 'sdx sign']` with key path `account/<accountId>/runtime/<runtimeId>/action/<actionId>` and counterparty `'self'`, taken for self. The reader resolves the expected identifier for the outgoing epoch and for `newEpoch` and asserts that both observed identifiers appear in the expected pair. The order of the two signature slots is not pinned.
6. Additionally assert that the keyring's identity for `newEpoch` byte-equals `newIdentityPubKey_p256`, cross-checking the declared identity against the loaded one.
7. Confirm the anchoring input spends the then-current tip.
8. Insert the new epoch into the keyring if not already present.
9. Dispatch nothing to the application. Rotation is handled by the runtime; application state MUST NOT be mutated by a rotation.

On mismatch the Action is dead-lettered with a rotation identity-mismatch reason rather than dispatched.

#### 1.10.4 Replay across an epoch boundary [#1104-replay-across-an-epoch-boundary]

Replaying a window that crosses a rotation is mechanical: Actions before the rotation decrypt under the root for the old epoch, the rotation Action itself is dual-verified as above, and Actions after it decrypt under the new one.

If the required root is archived and not loaded, the reader MUST halt and request an operator-approved unsealing rather than skipping or guessing. This is expected during forensic replay and SHOULD NOT occur in steady-state operation. A reader SHOULD cache an unsealed root only for the duration of the replay window and re-seal it when the window completes.

#### 1.10.5 The keyring [#1105-the-keyring]

The keyring records, per epoch: the epoch number as primary key, the serialised configuration of the root provider, the identity public key on each curve, the creation time, the action and transaction identifiers of the rotation that introduced the epoch (null for epoch 0), the reason, and a status of `active` or `archived`.

At most one epoch is `active` at any time. The stored provider configuration MUST be sufficient to reinstantiate the provider but MUST NOT be sufficient to decrypt without the source material: a pointer to a mnemonic, not the mnemonic; a key handle, not the credentials that open it.

The keyring is the single authoritative record of which root decrypts which epoch. It MUST be backed up with at least the cadence of the runtime's main store. Losing it forces a rebuild by replaying the rotation Actions from the public audit layer.

#### 1.10.6 Registry lifecycle across rotation [#1106-registry-lifecycle-across-rotation]

* After rotating to epoch `N+1`, all new registry rows are written with that epoch.
* Rows from epochs at or below `N` are retained indefinitely and are never modified. They describe derivation identifiers a reader will still encounter on replay.
* The registry key rotates **independently** of the root. Rotating it decrypts and re-encrypts the registry in one atomic transaction and updates the pointer to the key's new location. It changes no derivation and no derivation identifier; only the at-rest encryption changes. The runtime continues to operate throughout.

#### 1.10.7 Failure modes [#1107-failure-modes]

* **Aborted before the rotation transaction confirms.** Nothing has changed on the public audit layer and the keyring has not been written. The operator retries from the construction step.
* **Confirmed, but the keyring update did not happen.** The audit layer has advanced to the new identity while the local keyring lags. This heals itself: the reader sees the rotation Action on the next boot and MUST insert the new epoch at dispatch time.
* **New root lost before it was archived.** The rotation is already public and the new identity is live, but the old root is by definition still accessible, since it signed the transition. Recovery is an immediate second rotation to a known-good root, advancing to epoch `N+2`. The runtime is write-frozen until that confirms; read topologies continue serving.
* **An archived root is compromised.** Every Action encrypted under that epoch is at risk. Current operations under a later epoch are unaffected. Re-encrypting history is impossible on an immutable substrate, so the response is at the governance level (disclose, re-issue affected attestations) rather than the cryptographic one.

#### 1.10.8 What rotation does and does not give you [#1108-what-rotation-does-and-does-not-give-you]

Rotation provides forward secrecy from the rotation point onwards: Actions after it are encrypted under the new root, and compromise of the new root alone does not expose anything written before it.

It is not retroactive, and this profile does not offer classical perfect forward secrecy. Derivation here is deterministic by design, because deterministic replay is a core property: a reader must be able to reproduce the exact keys a writer used, arbitrarily far in the future. Deterministic derivation and classical forward secrecy are in genuine tension, and this specification resolves the tension in favour of replay and says so plainly rather than implying a property it does not have.

What the profile does provide is per-Action and per-field key isolation (compromise of one field's key reveals nothing about its siblings), counterparty isolation (compromise of one counterparty's root exposes only that pair's key universe), temporal bounding through epochs, and the enumeration barrier of §1.9. Compromise of a root remains catastrophic for the epochs it served. Deployments MUST protect it accordingly: secret-sharing or hardware custody, archived roots kept offline rather than online, and a registry key in a separate trust domain.

### 1.11 Security considerations [#111-security-considerations]

#### 1.11.1 What an observer of the public audit layer can see [#1111-what-an-observer-of-the-public-audit-layer-can-see]

| Component              | Visible                                                     | Derivable by an observer                                      |
| ---------------------- | ----------------------------------------------------------- | ------------------------------------------------------------- |
| Namespace              | Yes; it is a published, well-known list                     | Trivially                                                     |
| Security level         | Yes; always 2 in this profile                               | Trivially                                                     |
| Transaction identifier | Yes                                                         | Trivially, but it is not part of any derivation identifier    |
| `actionId`             | In the envelope header, to anyone who can read the envelope | Opaque and time-sortable, but not predictable before issuance |
| `accountId`            | No                                                          | No; opaque random                                             |
| `runtimeId`            | No                                                          | No; opaque random                                             |
| `fieldName`            | No; encrypted inside the envelope                           | Only by decrypting the envelope                               |
| `counterparty`         | Public for cross-party derivations; implicit when `'self'`  | Trivially when public                                         |

An attacker holding the root keying material but not the registry can derive a key only by guessing a complete derivation identifier. Because the account identifier, runtime identifier and field names are all outside the publicly visible data, enumeration requires either registry access or envelope decryption. Observing one decrypted envelope reveals that Action's identifier and the account and runtime pair, which enables enumeration of field keys **for that one Action**, not across the runtime's history.

#### 1.11.2 Separation of trees [#1112-separation-of-trees]

Distinct namespaces guarantee that a key derived for signing cannot be substituted as an encryption key or the reverse: derivation is deterministic per namespace, and different namespaces produce unrelated key universes. The derivation library does not enforce the separation, so implementations MUST.

The same key-path grammar applies to both curves, and the two trees are seeded from independent HKDF labels, so the same logical path yields independent keys on each curve.

#### 1.11.3 Delegation-scoped keys [#1113-delegation-scoped-keys]

A delegation-scoped key path encodes the actor's public key. If an actor rotates their own keys, new grants with the new key produce new key paths; existing grants remain bound to the old key. Ending an actor's authority is a revocation (§2.6), not a key rotation.

#### 1.11.4 Implementation hazards [#1114-implementation-hazards]

* P-256 implementations vary in their constant-time guarantees. Implementations MUST use a curve library that documents constant-time scalar multiplication for secret scalars, and MUST re-verify that property if the library is changed.
* The profile's labels and namespaces are the values most likely to be silently edited by a well-meaning refactor. Each MUST live in a single named constant, referenced everywhere, so that a change is visible in one place and caught by the test vectors.
* A profile value that reaches a derivation from configuration MUST be validated against the grammar of §1.3 at load time, not at first use. A malformed namespace discovered on the first write is discovered too late.

### 1.12 Conformance vectors [#112-conformance-vectors]

Conformance vectors are **profile-relative**: a derived key is a function of the profile as much as of the root keying material, so the pinned bytes in any vector belong to the profile they were computed under. Any vector values shown or referenced in this document are computed under the example profile of §1.3.1. A deployment derives its own vector set from its own published profile, and two deployments with different profiles will legitimately produce different bytes for the same test.

A conforming implementation MUST publish and pass known-answer tests, computed under its own profile, covering at least:

1. **Root split.** At least three fixed 64-byte root values, each pinning the resulting 32-byte secp256k1 and P-256 seeds in hexadecimal. The values MUST be independently reproducible with a general-purpose HKDF tool given the same root, empty salt, SHA-256 and the deployment's own per-curve labels.
2. **secp256k1 cross-check.** For a pinned seed, a derived symmetric key for a fixed key path and namespace at counterparty `'self'`, cross-verified against an independent implementation of the derivation standard.
3. **P-256 derivation.** For a pinned seed, the derived 32-byte private scalar and 33-byte SEC1-compressed public key, reproducible step by step from general-purpose curve and HMAC primitives following §1.8.2.
4. **ES256 round trip.** A signature over a fixed payload that verifies under a general-purpose JOSE library with the matching JWK, plus rejection of tampered signatures and of a wrong signer's key.
5. **Counterparty symmetry.** For a pinned pair of key holders and one namespace and key path, both sides derive byte-identical keys, and one side's derived public key equals the other side's derived private key's public key. Required on both curves.
6. **Curve independence.** Over at least ten random roots, the two per-curve seeds differ in at least 100 of 256 bits. This is a regression signal against accidentally unified or emptied labels, not a proof of independence; the independence argument rests on HKDF itself.
7. **Scalar rejection.** A construction that yields a scalar of `0`, a scalar equal to `N`, and a scalar greater than `N` MUST each raise the typed rejection error naming the curve; scalars of `1` and `N - 1` MUST be accepted.
8. **Normalisation.** A key path whose field name contains a combining character (for example `a` followed by U+0301) MUST normalise to the composed form before hashing, with the resulting key pinned.
9. **Derivation identifier assembly.** A fixed triple of security level, namespace and key path pinning the exact wire-form string.
10. **Grammar rejection.** An unregistered level-4 purpose MUST be rejected by the key-path validator; each purpose registered in the deployment's profile, and the session level-3 variant, MUST be accepted.
11. **Profile conformance.** Every string in the deployment's profile MUST satisfy the grammar and length rules of §1.3 and §1.6, and the profile's six namespaces and two per-curve labels MUST each be mutually distinct. A deployment publishes this result alongside its profile, so a consortium member can check a counterparty's profile before deriving anything against it.

***

## 2. Identity, mandates and delegation [#2-identity-mandates-and-delegation]

### 2.1 Model [#21-model]

An SDX identity is a W3C Decentralized Identifier. Delegation is the only identity-scoping mechanism in this version: a runtime's root grants scoped authority to an actor by emitting a system Action on the public audit layer, and every Action an actor performs carries a reference back to that grant.

The design has one governing property, from which most of the rules below follow: **a grant pins the actor's signing key as a snapshot, and verification compares against that snapshot**. A verifier never resolves a DID while deciding whether to accept an Action. DID resolution happens once, at grant issuance, and thereafter only in background audit checks.

This costs transparent key rotation and buys determinism. A verifier that resolved DIDs on the dispatch path would inherit a liveness dependency (the actor's DID endpoint going down halts dispatch), a latency cost on every Action, a censorship vector, and the unsolved problem of resolving a DID document *as it stood* at the Action's declared time. Pinning removes all four. Rotation remains achievable, as an explicit and auditable pair of Actions rather than an implicit consequence of someone editing a document elsewhere (§2.9).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119.

### 2.2 Terminology [#22-terminology]

**Actor.** A party controlling the private keys bound to a DID. Distinct from the runtime's own identity.

**Grant.** The `_grantDelegation` Action on the public audit layer that establishes a delegation.

**Revocation.** The `_revokeDelegation` Action on the public audit layer that ends a grant before its natural expiry.

**`delId`.** The opaque random 128-bit identifier of a grant, assigned when it is issued and carried in the envelope header of every Action performed under it.

**Actor key snapshot.** The P-256 (and reserved secp256k1) public keys recorded in the grant at issuance. This is the enforcement anchor. Later changes to the actor's DID document do not change it.

**Mandate credential.** An optional W3C Verifiable Credential, in SD-JWT form, that projects a grant into a form the wider SSI ecosystem can consume. It is never required for verification.

**Delegation chain.** In this version a chain always has length 1. The term is retained for a future version that may allow sub-delegation; verifiers MUST reject a chain longer than 1 today.

### 2.3 The grant (normative) [#23-the-grant-normative]

A grant is emitted only by the runtime's root: header signer scope `root`, no delegation reference present, signed by the runtime's P-256 identity key for the active epoch.

```
f    = "_grantDelegation"
args = canonical CBOR map:

  "delId"            : bstr(16)     -- opaque random, 128 bits from a CSPRNG
  "actorDid"         : tstr         -- MUST be the did:key pseudonym; see §2.12
  "actorPubKey_p256" : bstr(33)     -- SEC1-compressed P-256
  "actorPubKey_k1"   : bstr(33)     -- SEC1-compressed secp256k1; reserved, see below
  "scope"            : [ tstr+ ]    -- one or more method or query names
  "expiresAt"        : uint | null  -- milliseconds since the Unix epoch; null = no natural expiry
  "purpose"          : tstr ?       -- optional operator-readable label
  "vcHash"           : bstr(32) ?   -- optional SHA-256 of the mandate credential
  "meta"             : map ?        -- optional, operator-controlled
```

Field rules:

* `delId` MUST carry 128 bits of CSPRNG entropy. The writer SHOULD reject a freshly drawn value that already exists locally. A verifier MUST reject a grant whose `delId` already exists in its projection and MUST treat the collision as an integrity failure rather than an update, because grants are immutable and a repeated identifier can only be corruption or an attack.
* `actorPubKey_p256` MUST be exactly 33 bytes. At issuance it MUST have been confirmed present in the actor's DID document as a verification method referenced from `assertionMethod` (§2.10). Verifiers trust that this was done; they do not repeat it.
* `actorPubKey_k1` MUST be exactly 33 bytes and MUST be present in the grant. It is **not read on the dispatch path** in this version. It is recorded for future actor-submitted anchoring, for actor-initiated mutual authentication with external services on the actor's own behalf, and for uniformity with wallet identity models. When the actor's resolved DID document publishes no secp256k1 key, the field MUST be recorded as **33 zero bytes**, an explicit and unambiguously detectable "no key" sentinel. It MUST NOT be filled with a copy of the P-256 key, which would be indistinguishable from a real value.
* `scope` MUST be a non-empty array of names. See §2.5.
* `expiresAt` MAY be null. Operators SHOULD prefer a finite expiry; an unbounded grant can only be ended by an explicit revocation, and the cost of that is paid later, under pressure.
* `vcHash`, when present, is the SHA-256 of the mandate credential issued alongside the grant (§2.11), anchoring that credential to the record on the audit layer.
* `purpose` and `meta` are audit-grade. They MUST NOT be load-bearing for any verification decision, and they are subject to the content restrictions of §2.12.

### 2.4 Audit-layer placement of the system Actions (normative) [#24-audit-layer-placement-of-the-system-actions-normative]

The audit-layer payload of an Action is the envelope's field set, not the caller-level argument array. A system Action whose arguments are not projected into envelope fields writes an empty body and cannot be replayed into a projection, which would make grants unreplayable and therefore unverifiable after a rebuild.

Therefore:

1. `_grantDelegation` MUST project every present argument into the envelope's fields: the mandatory `delId`, `actorDid`, `actorPubKey_p256`, `actorPubKey_k1`, `scope` and `expiresAt`, plus whichever of `purpose`, `vcHash` and `meta` are set. `_revokeDelegation` MUST likewise project `delId` and, when present, `reason`.
2. Each such field is carried as signed-audit content placed on the audit layer (`sn = 'au'`, `pl = 'ch'` in the envelope encoding). The audit layer's content is decryptable by the runtime operator and the designated audit recipients; it is not world-readable clear text. See the envelope section for the placement model.
3. Field contents remain bound by §2.12.
4. A round trip MUST hold: a grant or revocation admitted and decoded back from the public audit layer MUST reconstruct exactly the arguments that the projection of §2.8 reduces into a delegation row. Carrying the arguments only in the caller-level array does not satisfy this.

Each field's name MUST match the corresponding argument key, so that a verifier reading a single field by name (as the self-revocation check of §2.7 does) reads the same value the projection does.

### 2.5 Scope grammar (normative) [#25-scope-grammar-normative]

`scope` is a literal, non-empty array of strings. Each string is either a method name or a query name; the two share one flat namespace, and an application MUST NOT declare a method and a query with the same name.

* Each name MUST NOT begin with `_`. Underscore-prefixed names are reserved for system Actions.
* Each name MUST be non-empty and free of control characters.
* Each name appears at most once. A verifier MUST deduplicate before checking.
* Scope is **closed-world**: invoking anything not in the array is a verification failure. The single exception is an actor revoking its own grant (§2.7).
* No wildcards, no exclusions, no argument predicates. A grant that means "everything except X" cannot be written, and that is deliberate.
* A grant naming a method that does not exist is not rejected at issuance, since methods may be added later. An invocation of an unknown name is rejected at dispatch by the runtime.
* An application MAY declare a set of public queries whose names bypass the scope check entirely. These are callable without a token, and scope grammar does not apply to them.

A verifier MUST treat a grant row whose scope violates this grammar (empty, or containing a reserved underscore-prefixed name) as invalid and dead-letter Actions under it, rather than evaluating the scope check against it. The projection is a trust boundary like any other.

Literal lists are unambiguous and trivially audited, and the scope check reduces to a membership test. The friction of enumerating methods is intended: wide-scope grants should be uncomfortable to write.

### 2.6 Revocation (normative) [#26-revocation-normative]

```
f    = "_revokeDelegation"
args = canonical CBOR map:

  "delId"  : bstr(16)
  "reason" : tstr ?     -- optional, operator-controlled; subject to §2.12
```

* A **root revocation** carries signer scope `root` and no delegation reference.
* An **actor self-revocation** carries signer scope `delegate` and a delegation reference of exactly `[delId]`, where that `delId` is the grant being revoked. See the carve-out in §2.7.
* Revoking a grant that does not exist, is already revoked, or has already expired is a no-op. The verifier logs it at warning level and changes nothing. See §2.13 for why the no-op matters more than it looks.

This version ships exactly two delegation verbs. There is no update verb (grants are immutable), no sub-delegation verb, no extension verb (to extend, re-grant), and no re-key verb (to rotate, revoke and re-grant, §2.9).

### 2.7 Verification (normative) [#27-verification-normative]

Delegation verification runs after the envelope is decoded and **before** the Action is dispatched to the application.

The envelope header fields it uses are:

```
hdr.pk    signer public key, 33 bytes SEC1-compressed P-256
hdr.pks   "root" | "delegate"
hdr.dref  [ delId ]   -- absent when pks is "root"; exactly length 1 when "delegate"
hdr.f     the invoked method name
hdr.tm    the writer-declared time, milliseconds since the Unix epoch
hdr.ep    the key epoch
hdr.aid   the action identifier
```

The header does **not** carry the actor's DID. A verifier resolves `dref[0]` to a grant, and the grant carries the pseudonymous identifier. This keeps the envelope small and avoids repeating a DID string on every Action.

#### 2.7.1 Root scope [#271-root-scope]

```
if hdr.dref is present:
    dead-letter "delegation-invalid"          -- mixed scope
if verified payload signer key-id != expected per-Action signing key for (hdr.aid, hdr.ep):
    dead-letter "root-pk-mismatch"
if hdr.pk != verified payload signer key-id:
    dead-letter "root-pk-mismatch"
proceed to dispatch
```

Note carefully what `hdr.pk` is for a root Action: it is the **per-Action derived signing key** for `hdr.ep`, computed per §1.10.3 step 5, not the runtime's raw identity key. The decoder verifies the payload signature under the key identifier the signature itself declares, so the admission layer is what binds `hdr.pk` to that verified identifier. Comparing `hdr.pk` against the raw identity key instead would reject every genuine root Action.

#### 2.7.2 Delegate scope [#272-delegate-scope]

```
if hdr.dref is absent:                    dead-letter "delegation-invalid"  (bad-dref-length)
if hdr.dref.length != 1:                  dead-letter "delegation-invalid"  (bad-dref-length)

delId = hdr.dref[0]
grant = delegations.get(delId)

if grant is null:                         dead-letter "delegation-invalid"  (unknown-grant)
if grant.delId != delId:                  dead-letter "delegation-invalid"  (dref-mismatch)
if grant.revokedAt != null
     and grant.revokedAt <= hdr.tm:       dead-letter "delegation-invalid"  (grant-revoked)
if grant.expiresAt != null
     and grant.expiresAt <= hdr.tm:       dead-letter "delegation-invalid"  (grant-expired)
if grant.actorPubKey_p256 != hdr.pk:      dead-letter "delegation-invalid"  (signer-mismatch)

-- self-revocation carve-out, see below
if hdr.f == "_revokeDelegation":
    if the recorded revoke target delId != hdr.dref[0]:
        dead-letter "delegation-invalid"
    proceed to dispatch

if hdr.f not in grant.scope:              dead-letter "delegation-invalid"  (out-of-scope)

proceed to dispatch
```

Additionally, the decoder verifies each payload signature under the key identifier the signature declares, so the verifier MUST assert that a delegate Action carries exactly one verified signature whose key identifier equals the hexadecimal of `hdr.pk`. A mismatch is `delegation-invalid`. This mirrors the root-scope binding above: in both cases the header claims a signer and the verifier must prove that the claimed signer is the one that actually signed.

Revocation is terminal and is evaluated before expiry. The boundary comparison is `<=` in both cases: a grant revoked or expired exactly at `hdr.tm` does not authorise that Action.

The typed sub-reasons (`unknown-grant`, `grant-revoked`, `grant-expired`, `signer-mismatch`, `out-of-scope`, `bad-dref-length`, `dref-mismatch`) MUST be carried in the dead-letter's detail payload. All delegate-scope failures use the category `delegation-invalid`; root-scope signer failures use `root-pk-mismatch`. The distinction matters operationally: one means "this actor may not do this", the other means "this does not appear to be the runtime".

**The self-revocation carve-out.** An actor may revoke its own grant, but `_revokeDelegation` is underscore-prefixed and so can never appear in a scope array (§2.5). Without a carve-out, the scope check would reject every self-revocation. The carve-out is deliberately narrow:

* It applies only to the literal method `_revokeDelegation`, recognised by an explicit verb constant rather than inferred from the ordering or the wording of any other check.
* Every other gate still runs. Reaching the carve-out already proves that the actor controls the grant referenced in `dref[0]`, because the signer-key comparison passed.
* The **target** is then bound to the authorising grant: the verifier reads the `delId` from the revocation's audit-layer fields and dead-letters unless it equals `dref[0]`. A missing, wrong-typed or mismatched target fails closed. Without this binding, an actor holding grant A could revoke a third party's grant B, which is a straightforward privilege escalation.
* Every other underscore-prefixed or out-of-scope method still dead-letters.

An admitted self-revocation can therefore only revoke the grant that authorises it.

#### 2.7.3 Time basis and backdating [#273-time-basis-and-backdating]

Expiry and revocation are evaluated against `hdr.tm`, the writer-declared time, never against the wall clock. This is what makes verification replay-deterministic: the same Action, replayed at any point in the future, yields the same verdict.

That determinism creates an obvious attack: a compromised actor could backdate `hdr.tm` to a moment before their grant was revoked. Two bounds compose against it:

1. **Writer-side monotonicity.** Because `actionId` is a ULID, its embedded timestamp is checkable. An honest writer produces action identifiers within about 5 seconds of its own clock and SHOULD refuse to construct an Action whose declared time drifts further than that.
2. **Verifier-side admission tolerance.** The verifier compares `hdr.tm` against the time the Action was admitted by the network and dead-letters with an integrity failure when the difference exceeds a configurable tolerance. The default is &#x2A;*300,000 milliseconds (5 minutes)**.

The tolerance is deliberately wider than a naive reading suggests it should be. The admission time available to a verifier on the read path is its own clock at the moment the Action arrives, which legitimately lags true admission by network propagation, the verifier's polling interval and the actor's clock skew. A tight bound drops honest Actions. The proxy is never *weaker* than true admission time, since a verifier only sees an Action after the network has admitted it, so the measured skew is always at least the true skew; the cost of the proxy is false positives, not missed attacks.

A live admission whose admission time cannot be resolved MUST fail closed with an integrity failure rather than skipping the check. Resynchronisation and backfill skip the check, since historical Actions are being replayed and the comparison is meaningless there.

Operators scheduling a revocation SHOULD assume up to the configured tolerance of backdating is achievable and add that buffer. The symmetric concern, an operator backdating a revocation to retroactively invalidate legitimate Actions, is not addressed cryptographically: a runtime's root emits revocations at current time, and detection is a matter of operator policy and audit logs.

#### 2.7.4 Ordering [#274-ordering]

A grant and the first Action that references it MAY arrive in any order. A verifier's reorder buffer holds a delegated Action whose grant has not yet arrived, until the grant arrives or the reorder timeout fires. Implementations MUST NOT reject on first sight of an unknown grant if a reorder buffer is in use.

#### 2.7.5 The DID is never consulted at dispatch [#275-the-did-is-never-consulted-at-dispatch]

The verifier MUST NOT resolve `actorDid` on the dispatch path, and the verification function MUST NOT read the field at all. Everything needed for the decision is the pinned key, the lifecycle timestamps and the scope. This is a hard rule, not a performance preference: it is what keeps dispatch free of a network dependency and it is what keeps the verdict identical on replay.

Operators who want to detect "the actor's DID document no longer lists the pinned key", a possible compromise signal, run a **separate background check** that resolves each active grant's real DID from the identity-link store (§2.12) and compares the document against the pinned keys. Divergence raises an operator alert. It MUST NOT auto-revoke: revocation is an explicit decision.

### 2.8 The delegations projection [#28-the-delegations-projection]

A verifier maintains a local projection built solely by replaying `_grantDelegation` and `_revokeDelegation` Actions in canonical order. The public audit layer is authoritative; the projection is a cache and MUST be rebuildable from it.

```
DelegationRow {
  delId              string    -- hexadecimal, 32 characters (16 bytes); primary key
  runtimeId          string    -- local field name; the projection is not interop state
  grantActionId      string    -- action identifier of the grant
  actorDid           string    -- did:key pseudonym only, see §2.12
  actorPubKey_p256   string    -- 66 hexadecimal characters, SEC1-compressed
  actorPubKey_k1     string    -- 66 hexadecimal characters
  scope              string[]
  expiresAt          number | null
  purpose            string | null
  vcHash             string | null   -- hexadecimal SHA-256 of the credential, when issued
  meta               map | null
  grantedBy          string    -- runtime identity public key at the emitting epoch;
                               -- the actor's own key for a self-revocation
  grantedAt          number    -- from the grant Action's hdr.tm
  revokedAt          number | null
  revokedByActionId  string | null
}
```

Comparison conventions a verifier MUST follow: the header's 33-byte signer key compares against the row's 66-character hexadecimal by case-insensitive hexadecimal equality, and the header's 16-byte delegation reference compares both against the key the caller looked up by **and** against the row's own `delId`. Checking both is defence in depth against a misindexed projection returning the wrong row.

The lifecycle decision (active, revoked, expired at a given instant) MUST be computed by a single shared predicate, used by the verifier, by any query surface and by any operator tooling. Three separate implementations of "is this grant still good" will eventually disagree, and the one that disagrees in the permissive direction is the security bug.

### 2.9 Lifecycle and the rotation consequence [#29-lifecycle-and-the-rotation-consequence]

```
granted --> active --> revoked      (explicit, via _revokeDelegation)
                   --> expired      (time-based, at expiresAt)
```

Both end states are terminal. A revoked grant that later reaches its expiry stays revoked. A grant may be revoked after expiry; that is harmless and is a logged no-op (§2.13).

**The pinning consequence.** If the actor updates their DID document, adding a verification method or removing one, the grant's pinned key stays in force. The old key continues to verify for the grant's scope until the grant expires or is revoked. Signatures from newly published keys do **not** verify, no matter how correct the new DID document is.

Rotating an actor's keys is therefore an explicit three-step procedure:

1. The actor (or the operator) updates the DID document: add the new verification method, remove or deprecate the old one.
2. The operator emits `_revokeDelegation` for the existing grant.
3. The operator emits `_grantDelegation` with a new `delId`, the new pinned key, the same scope and an adjusted expiry.

The rotation is visible on the public audit layer as two Actions, which is a clean audit trail: every change in who can act is an explicit, timestamped, signed event rather than a silent consequence of an edit to a document hosted elsewhere.

The trade-off is real and should be stated: deployments with high actor-key rotation frequency pay one operator round trip per rotation, and grant issuance depends on the actor's DID endpoint being reachable at that moment. Deployments that need transparent rotation can pre-check the document themselves; deployments that do not (most) get a verifier with no network dependency at all.

### 2.10 Grant issuance [#210-grant-issuance]

Issuance is the one point where a DID is genuinely resolved.

#### 2.10.1 Supported methods [#2101-supported-methods]

**`did:web:<fqdn>[:<path>]`** for persistent and organisational actor identities.

* The document MUST be fetched from `https://<fqdn>/.well-known/did.json`, or `https://<fqdn>/<path>/did.json` for the sub-path form.
* HTTPS is mandatory. Plain HTTP MUST be rejected.
* The document MUST be valid W3C DID Core 1.0 with at least one verification method whose `publicKeyJwk` or `publicKeyMultibase` encodes the P-256 key to be pinned, and `assertionMethod` MUST reference that verification method.

Fetch policy at issuance (this policy is never applied on the dispatch path, which performs no fetches at all):

| Parameter             | Value                                                                                                                              |
| --------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| Connect timeout       | 10 seconds                                                                                                                         |
| Read timeout          | 10 seconds                                                                                                                         |
| Maximum redirects     | 3, and each redirect MUST stay within the same authority or be a same-origin sub-path; cross-origin redirects MUST be rejected     |
| Maximum document size | 256 KiB                                                                                                                            |
| Retries               | 3 attempts total, exponential backoff with jitter, on network errors and 5xx                                                       |
| Give up               | On any 4xx (permanent) or three consecutive 5xx                                                                                    |
| Cache                 | Honour `Cache-Control: max-age` up to 1 hour at issuance; a background audit scanner MUST use a separate cache capped at 5 minutes |

**`did:key:<multibase-pubkey>`** for ephemeral session identities, where the public key *is* the identifier.

* The document is derived deterministically from the identifier itself. There is no external resolution and no infrastructure to operate.
* The encoded key MAY be P-256 (multicodec code point `p256-pub` = `0x1200`, encoded as the two-byte unsigned varint `0x80 0x24`) or secp256k1 (`secp256k1-pub` = `0xe7`, encoded as `0xe7 0x01`). The full form is `did:key:z<base58btc(varint(codepoint) || compressedPubkey)>`, where `z` is the multibase base58btc prefix.
* Session use in this version is P-256 only, since sessions sign envelopes.

Other DID methods MUST be rejected at issuance in this version.

#### 2.10.2 Issuance procedure (normative) [#2102-issuance-procedure-normative]

1. Resolve the actor's supplied real DID (`did:web` by fetch, `did:key` deterministically).
2. Find the first verification method carrying P-256 material that is referenced from `assertionMethod`.
3. Extract its compressed public key and use it as `actorPubKey_p256`.
4. If the document publishes a secp256k1 verification method, extract it as `actorPubKey_k1`; otherwise record the 33-zero sentinel of §2.3. For a generated session (§2.14), record the session's own generated secp256k1 key, which exists independently of any document; the sentinel applies only when a resolved document publishes no such key.
5. Optionally issue a mandate credential (§2.11), compute its SHA-256 and place it in `vcHash`.
6. Derive the `did:key` form of the pinned P-256 key and use **that** as the `actorDid` written to the audit layer. Record the actor's real resolvable DID, and any retained credential, off the audit layer in the identity-link store keyed by `delId` (§2.12).
7. Construct and emit the `_grantDelegation` Action.

Issuance MUST fail if resolution fails, if the document lacks a P-256 verification method referenced from `assertionMethod`, or if the supplied DID uses an unsupported method.

#### 2.10.3 Trust in the resolved document [#2103-trust-in-the-resolved-document]

Resolving `did:web` trusts the fqdn's HTTPS endpoint. An attacker controlling that endpoint, or controlling DNS together with a fraudulent certificate, can serve a tampered document. Because resolution happens only at issuance, the attack window is the moment of issuance rather than every Action, and the pinned key means later tampering cannot change who an existing grant authorises. Operators SHOULD verify out of band that an actor controls the domain before issuing, and MAY require an additional trust anchor for high-value grants.

`did:key` is self-issued by construction: anyone can produce one for a key they hold. That is the point, and it is what makes it zero-infrastructure. Trust does not come from the identifier; it comes from the operator who chose to issue a grant referencing it. Issuing a grant to a `did:key` is the operator attesting that the key holder is authorised under the operator's own policy.

### 2.11 The mandate credential (optional) [#211-the-mandate-credential-optional]

A grant MAY be projected into a W3C Verifiable Credential for consumption by SSI tooling. The credential is never required for verification: everything a verifier needs is in the grant on the audit layer. Deployments with no SSI interoperability requirement can skip credential issuance entirely and lose nothing.

Format is SD-JWT. Payload shape:

```json
{
  "iss": "<runtime root DID>",
  "sub": "<actor DID>",
  "vct": "urn:sdx:Mandate:v1",
  "iat": 1767225600,
  "exp": 1798761600,
  "mandate": {
    "runtimeId": "<runtimeId>",
    "delId": "<hexadecimal>",
    "scope": ["<method names>"],
    "purpose": "<optional string>"
  },
  "cnf": {
    "jwk": { "kty": "EC", "crv": "P-256", "x": "<base64url>", "y": "<base64url>" }
  }
}
```

The credential type identifier shown here, `urn:sdx:Mandate:v1`, is an **example profile value** (§1.3.1): a deployment fixes its own and publishes it, and its claim vocabulary travels with it. Whatever the value, it sits inside the signed credential and therefore inside the digest anchored as `vcHash`, so external verifiers match it byte for byte and it cannot be changed within a deployment without invalidating every credential already issued under it.

The credential is signed by the runtime's root with ES256 under its P-256 identity key. The confirmation key in `cnf.jwk` is the actor's pinned signing key, so a holder-bound presentation is checkable against the same key the grant pins.

**Time units are the classic failure here and are normative.** `iat` and `exp` are **seconds** since the Unix epoch, per the JWT NumericDate convention. The grant times recorded on the audit layer are **milliseconds**. The issuer MUST convert:

```
iat = floor(grantTimeMs / 1000)
exp = expiresAtMs == null ? <omit the field entirely> : floor(expiresAtMs / 1000)
```

An implementation that skips the conversion produces a credential whose expiry is roughly a thousand times too far in the future, which conforming SD-JWT verifiers reject. For a grant with no expiry the field MUST be omitted entirely rather than emitted as null.

**Anchoring.** When a credential is issued, `SHA-256(credential bytes)` is recorded in the grant's `vcHash`. Any party holding the credential can then check that it matches the grant. The credential itself is delivered off the audit layer, by direct handoff, an HTTPS endpoint, a DIDComm exchange or a wallet presentation. Credentials SHOULD be treated as semi-sensitive: one exposed in a public location reveals the actor's identifier, the grant's scope and the runtime, which is targeting information even though it confers no ability to act without the actor's private key.

### 2.12 Pseudonymous identity on the audit layer, and erasability [#212-pseudonymous-identity-on-the-audit-layer-and-erasability]

Delegated actors can be natural persons. A grant records identity immutably on a public, append-only layer, while data-protection law gives a natural person a right to erasure (GDPR Article 17 in the European Union, with equivalents elsewhere). An append-only layer cannot delete an entry. This section resolves that tension, and it does so structurally rather than cryptographically.

#### 2.12.1 Why cryptographic erasure does not work here [#2121-why-cryptographic-erasure-does-not-work-here]

The intuitive design is to store the identity encrypted under a per-subject key and destroy the key on request. That does not work in this architecture. Every key here is **derived**, deterministically, from root keying material the runtime retains (§1.8). A derived key is a function of `(root, counterparty, derivation identifier)`, so the holder of the root can always recompute it. Destroying a derived key erases nothing.

Real erasure requires either destroying entropy that exists nowhere in retained material, or keeping the linkable data off the immutable substrate entirely. This specification takes the second route. Note that this reasoning applies to data *encrypted* onto the audit layer too: because the decryption key is permanently recomputable from the retained root, personal data encrypted onto the audit layer remains permanently decryptable and therefore is not erased by anything short of destroying the root.

#### 2.12.2 Audit-layer identity is a pseudonym (normative) [#2122-audit-layer-identity-is-a-pseudonym-normative]

For **every** actor, natural or organisational, the `actorDid` on the audit layer MUST be the `did:key` form of `actorPubKey_p256`. This is a deterministic one-to-one encoding of the pinned key: it adds no information the grant does not already carry, and it needs no document fetch to interpret.

A resolvable DID method MUST NOT appear in the `actorDid` recorded on the audit layer. An actor's real resolvable DID, where one exists, lives off the audit layer (§2.12.3).

A natural person's directly identifying data (name, national identifier, resolvable real DID, user identifier, case identifier) MUST NOT be written to the audit layer in any field, in clear, hashed, or encrypted form.

`purpose`, `vcHash` and `meta` remain optional and operator-controlled; the operator is the data controller and is responsible for their contents. `meta` and the revocation `reason` MUST NOT carry a natural person's erasable data, and a revocation issued as part of an erasure omits `reason` entirely. A value that genuinely must be anchored SHOULD get a typed non-identifying field rather than being dropped into the free-form bag.

`vcHash` MAY be anchored unconditionally. It commits to a full credential, held off the audit layer, that is deleted on erasure, after which the hash commits to a high-entropy document that no longer exists, is not reversible and is not linkable to anything. It is inert, in the same sense that the pinned public key is inert. This is a different case from anchoring a hash of an identifier *as itself*, which remains a persistent handle to the person and is prohibited by the rule above.

A **fail-closed guard at grant emission** MUST reject any grant whose `actorDid` is not the `did:key` derived from `actorPubKey_p256`. The guard enforces that rule alone; the optional fields remain the operator's responsibility. Error text and logs about a rejected identifier MUST NOT echo the raw value: they carry a redacted descriptor of the form `method=<safe-label>, len=<n>`, where the method label is emitted only when it matches a strict method-name grammar within a length bound and otherwise collapses to a fixed placeholder. A guard that rejects a resolvable DID and then writes it verbatim into a log has moved the problem, not solved it.

Why `did:key` and not a pairwise or peer method: the byte-equivalent alternatives add multi-key support, service endpoints and offline pairwise resolution, none of which a single-runtime grant uses. `did:key` is the irreducible pseudonym.

#### 2.12.3 The identity-link store (normative) [#2123-the-identity-link-store-normative]

The mapping from pseudonym (`delId`, pinned key) to real-world identity (the actor's resolvable DID, personal data, any retained credential, and whether the actor is a natural or legal person) lives in an operator-hosted identity-link store, keyed by `delId`.

It MUST NOT be written to the audit layer, MUST NOT be replicated to the distribution network, and MUST NOT be reconstructable by replay. An implementation ships the schema and the write, lookup and delete operations; the operator hosts the data, in a region compliant with its own residency policy, and is its controller.

The natural-versus-legal-person distinction is a column in this store, not a field on the audit layer. Because the grant on the audit layer is pseudonym-only for everyone, its encoding is uniform and reveals nothing by its shape.

#### 2.12.4 Two-tier attribution (normative) [#2124-two-tier-attribution-normative]

* **Tier 1**, on the audit layer, free of personal data, permanent, survives erasure. `hdr.dref = [delId]` plus `hdr.pk` plus the grant prove: *the holder of key K, delegated by grant D, performed Action X within scope S*. This is the tier the verifier uses, and it never reads the DID.
* **Tier 2**, off the audit layer, erasable. *Key K is person P*, resolvable only through the operator's identity-link store, and only at audit-query time.

Attribution therefore survives erasure in the form that matters for integrity (which key, which grant, which scope) and disappears in the form that matters for privacy (which person).

#### 2.12.5 Resolution is query-time only (normative) [#2125-resolution-is-query-time-only-normative]

The pseudonym-to-person lookup MUST NOT be invoked inside the projection reducer or inside the verifier's decode path. It is an audit-query-time operation.

The consequence is precise and testable: the delegations projection is **byte-identical before and after an erasure**. There is no erased-marker in the projection; if a sentinel appears anywhere, it appears in the operator's query result, not in replayed state. This is what preserves the replay determinism of §2.7.3. A projection that changed as a side effect of an erasure would make the same Action verify differently before and after, which would be a correctness failure dressed as a privacy feature.

#### 2.12.6 Erasure procedure (normative) [#2126-erasure-procedure-normative]

On a verified erasure request, the operator:

1. Looks up all `delId` values for the subject in the identity-link store.
2. SHOULD emit `_revokeDelegation` on the audit layer for the affected grants, and confirm it durable, **before** the irreversible deletions in steps 3 and 4. The revocation names `delId`, not who, so it carries nothing erasable and is idempotent.
3. Hard-deletes the identity-link rows, or tombstones them with the identifying columns nulled, retaining only `{delId, erasedAt}` as a marker that erasure occurred. &#x2A;*This is the erasure.**
4. Deletes any retained copy of the mandate credential and any presentation or transaction logs that name the person.

The order is load-bearing. Emitting the revocation first makes the operation all-or-nothing: if a later step fails, the delegation is left revoked and the erasure retryable. The reverse order can leave the identity-link row deleted while the delegation is still live, which is a working delegation that nobody can attribute. Because the revocation carries nothing erasable, emitting it early retains nothing, and a retry re-emits it harmlessly.

Nothing on the audit layer, in the distribution network, or in the projection is mutated, because none of them ever held a linkable natural-person identifier. There is no cryptographic shredding, no data-encryption key and no salt to destroy. Deleting the identity-link row *is* the erasure.

#### 2.12.7 Erasure of an already-terminal grant (normative) [#2127-erasure-of-an-already-terminal-grant-normative]

When the revocation of step 2 targets a grant that is already terminal at the revocation Action's own time (already expired, or already revoked), the projection MUST treat it as a **logged no-op**: the reducer logs the event and does **not** set `revokedAt` or `revokedByActionId`. No marker is recorded against the dead grant. Expiry is judged at the revoking Action's own declared time, not the wall clock, so the no-op is replay-stable.

This is the intended semantics, not an oversight:

* An already-expired grant is terminal and is already excluded from every active listing at every instant at or after its expiry. It authorises nothing, so an extra marker adds no protection.
* Writing the marker would mutate the projection and break the byte-identical-before-and-after guarantee of §2.12.5, and with it replay determinism.
* The identity-link deletion has already removed the only linkable data. The audit layer, the network and the projection never held any.

For an already-terminal grant, the record of the erasure is the identity-link deletion plus the operator's audit log, not a marker on the audit layer. The operator still emits the revocation, because it is idempotent, harmless, and correct for grants that are still live.

#### 2.12.8 Residual exposure (stated, not solved) [#2128-residual-exposure-stated-not-solved]

The pinned public key is a permanent correlation handle inside the audit layer's encrypted content: every Action under one grant remains linkable to every other, for any party able to decrypt. If the operator's identity-link store leaks before an erasure, the subject can be re-identified. The mitigations are short-lived, one-key-per-session identifiers for natural persons (§2.14), and keeping the identity-link store as the single linkable artefact so that there is exactly one thing to protect and one thing to delete.

Hosting the identity-link store also makes a runtime deployment the technical home of that data, with the operator remaining its controller. A missed emission guard would put non-erasable data on an immutable substrate, which is why that guard is fail-closed rather than advisory.

### 2.13 Actor authority and its limits [#213-actor-authority-and-its-limits]

**Bounded compromise.** Actor keys are held by the actor, not by the runtime. A compromise is bounded to the grant's scope and its remaining lifetime. Prefer short-lived grants for sensitive operations; revoke immediately on suspicion.

**Grant forgery.** Only the runtime root's active-epoch P-256 identity key can emit a grant, and the grant's own envelope signature is verified like any other Action's. A compromised runtime root can of course issue arbitrary grants; that risk is governed by custody of the root (§1.10), not by this layer.

**Cross-runtime reuse.** A grant issued by runtime A cannot authorise Actions on runtime B. A verifier binds `delId` to its own local projection, so an actor presenting A's `delId` to B fails at lookup with `unknown-grant`. Authority does not flow between runtimes by delegation; it flows by handoff (§1.7).

**Method removal.** A grant keeps a method in its scope after the application removes the method. Invocations then fail at dispatch as an unknown method: the delegation stays valid and the specific call is a no-op. Operators who need this to be a hard failure emit explicit revocations.

**Deprecating a method** works through scope churn rather than a per-method flag: stop issuing grants containing it, let existing grants expire, then remove the implementation once no live grant carries it. This works cleanly when grants are short-lived, which is another reason to prefer finite expiry.

### 2.14 Delegated and session actor keys [#214-delegated-and-session-actor-keys]

#### 2.14.1 Dispatch-time verification is pubkey-pinned [#2141-dispatch-time-verification-is-pubkey-pinned]

The delegation key path of §1.6.1 exists for counterparty-symmetric derivation between a runtime and an actor, where both sides need to arrive at the same key from opposite directions. That derivation is **not** on the dispatch-time verification path in this version. An actor's envelope signing key is the raw pinned key from the grant's `actorPubKey_p256`, tied to their DID document's `assertionMethod` at issuance, and verification is a direct key comparison (§2.7.2). No derivation happens at verification time.

The derivation grammar is retained for flows where an actor anchors its own Actions, and for actor-initiated mutual authentication with external services. Where it is used, the parameters are:

```
namespace    = [2, 'sdx delegate']
keyPath      = account/<accountId>/runtime/<runtimeId>/delegation/<delId>/actor/<actorPubKey>
counterparty = the other party's identity key, never one's own:
               runtime side -> counterparty = actorPubKey
               actor side   -> counterparty = runtimeIdentityPubKey
```

Both derivations produce the same child key by the symmetry of §1.8.2. `actorPubKey` is the actor's hexadecimal public key on the curve the delegation declares: secp256k1 for audit-layer operations, P-256 for envelope signing.

Using a distinct namespace for delegated keys rather than the runtime's own signing namespace is what prevents a compromised actor from producing something that presents as a runtime-root Action.

#### 2.14.2 Short-lived session actors [#2142-short-lived-session-actors]

Ephemeral sessions are a first-class case, and `did:key` is the natural identifier for them because the key is the identifier and there is no infrastructure to stand up.

The pattern:

1. The operator issues a session grant with a narrow scope and a short expiry.
2. A fresh 64-byte root keying material is drawn for the session, and the session's P-256 and secp256k1 key pairs are self-derived from it under:

   ```
   namespace    = [2, 'sdx delegate']
   keyPath      = account/<accountId>/runtime/<runtimeId>/session/<sessionId>
   counterparty = 'self'
   ```

   The session is its own counterparty: the pair comes from the session's own fresh entropy, not from a shared secret. The key path carries no actor or grant component, because at generation time neither exists yet. It exists for hierarchy consistency and audit, not for re-derivation: the resulting public key is pinned raw in the grant, and the verifier only ever compares against that.
3. The `did:key` form of the session P-256 key becomes the `actorDid` recorded on the audit layer.
4. The grant is emitted with that identifier, the pinned key, a short expiry and a narrow scope. No natural-person identifier goes into `meta`; the subject mapping lives in the identity-link store keyed by `delId` (§2.12.3).
5. The caller receives a bundle of the grant identifier, an API token, the session private keys, the session identifier and the expiry, and signs Actions within scope for the session's lifetime.
6. When the lifetime elapses, the caller discards the keys. The grant remains on the audit layer with its original expiry and the verifier rejects post-expiry invocations automatically. **No revocation Action is required**, which is the main operational reason to prefer short expiry over open-ended grants plus cleanup.

Session key leakage grants scope authority for the remainder of the lifetime. Mitigate with genuinely short lifetimes, optional revocation, and monitoring of per-grant Action volume.

Actors with persistent identities are the common case and are the default; ephemeral sessions are an opt-in mode for genuinely transient flows. Actors hold their keys in their own wallets; a runtime integrates with wallets and MUST NOT custody actor keys. A session provider is a convenience, not a requirement: any root-key provider can back a session identity.

### 2.15 Conformance [#215-conformance]

A conforming implementation MUST demonstrate at least:

1. The emission guard rejects a grant whose `actorDid` is not the `did:key` derived from the pinned key, and its error text carries only the redacted descriptor.
2. The verification function never reads `actorDid`.
3. The projection reducer never reads the identity-link store, and the projection is byte-identical before and after an erasure.
4. The identity-link store supports row deletion, is not written to the audit layer, is not replicated to the network, and is not reconstructable by replay.
5. An erasure-driven revocation of an already-expired grant leaves `revokedAt` and `revokedByActionId` null and leaves the projection byte-identical.
6. A grant emitted through the real writer and decoded back from the audit layer reconstructs the arguments the projection reduces into a delegation row.
7. Every branch of the §2.7.2 decision tree dead-letters with its typed sub-reason, including a delegate Action whose verified signature key identifier does not equal `hdr.pk`.
8. The self-revocation carve-out accepts a self-revocation whose recorded target equals `dref[0]`, and rejects a missing, wrong-typed or mismatched target, as well as every other out-of-scope method.
9. Expiry and revocation are evaluated at the declared time, never the wall clock, so a replayed Action yields the same verdict at any future point.
10. A live admission exceeding the backdating tolerance dead-letters with an integrity failure, and a live admission with no resolvable admission time fails closed.
11. Mixed scope (root scope with a delegation reference present) and a delegate reference of length other than 1 are rejected at the header schema gate.
12. Mandate credential times are emitted in seconds, and the expiry field is omitted entirely for a grant with no expiry.
