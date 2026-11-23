<!-- tpnil:provenance-header -->
**TPNIL pinned source text.** SDX Protocol specification v0.1, dated 2026-07-17, revised 2026-09-01; keys, envelope and anchoring ratified 2026-09-01. This file holds the page *Base protocol specification v0.1*, the base specification, dated 2026-07-17 and revised 2026-09-01. Requirement citations use the clause prefix `BASE`.

- Source page: <https://sdxprotocol.org/protocols/data-sharing/v0.1/>
- Retrieved from: <https://sdxprotocol.org/llms.mdx/protocols/data-sharing/v0.1.md>, the site's Markdown rendition of the source page
- Retrieved at: 2026-11-11T05:08:31Z
- SHA-256 of the retrieved bytes: `944ad17b4b1237b4217d347739ae8995c923ac12befba500fc1829cd815f511f`
- Licence: SDX specification texts and test vectors licence, Version 1.0, 1 September 2026, Licensor mintBlue B.V. [Reference copy](../../../../../LICENSES/SDX-Specification-License-1.0.reference.txt)
- Modification: none. The retrieved bytes follow the closing marker of this header unchanged; TPNIL added only this header. Root-relative links in the text resolve against `https://sdxprotocol.org`.

Attribution: SDX Protocol specification, version 0.1 (2026-07-17, revised 2026-09-01). The source page is the canonical publication. This copy retains the SDX licence terms and is excluded from TPNIL's Apache-2.0 grant; see the [third-party notices](../../../../../THIRD_PARTY_NOTICES.md).
<!-- tpnil:upstream-text-follows -->
# Base protocol specification v0.1 (/protocols/data-sharing/v0.1)



> Status: Draft, pending technical review
> Version: 0.1
> Date: 2026-07-17, revised 2026-09-01 (Section 8)
> Normative sections, published 2026-09-01: [The record envelope and field placement](/protocols/data-sharing/v0.1/envelope), [Keys, identity and delegation](/protocols/data-sharing/v0.1/keys), [Anchoring, addressing and retrieval](/protocols/data-sharing/v0.1/anchoring). First test-vector suites: [Test vectors](/protocols/data-sharing/v0.1/vectors).
> This is the normative specification. The overview page orients and links, and does not repeat this content.
> Initiator and first maintainer: mintBlue (see Section 7, Governance). The initiator is not the owner.

## Abstract [#abstract]

The base protocol defines how organisations share, address, and verifiably record encrypted data directly with one another. It fixes a minimal normative core: the shape of a record, how parties are addressed, how each field is encrypted, how every exchange is anchored to a shared public audit layer, and how any party reconstructs and verifies state from the recorded log. On top of that core sits a forkable, source-available reference implementation, including the state machines that run the protocol, which is one way to satisfy the rules and not the standard itself. No single organisation owns the base protocol. The protocol is designed so that anyone holding this specification can build an interoperable implementation in any language. Full independent interoperability in this version depends on the published test-vector suites and on resolution of the settlement layer the audit layer resolves to (PROV-1); Section 6 sets out what an implementation can build against before those are pinned. This document carries the normative rules, the register-and-discovery chapter, the conformance requirements, the governance model, and the version history.

***

## 1. Introduction and scope [#1-introduction-and-scope]

### 1.1 What the base protocol is [#11-what-the-base-protocol-is]

The base protocol is the base layer for cross-organisational data sharing. It specifies **how** organisations exchange encrypted data: how a record is structured, how parties are addressed and discovered, how records are signed, how each field is encrypted, and how the fact of an exchange is recorded so that no participant can retrospectively alter it. It is deliberately minimal. It fixes only what two independent implementations MUST agree on to interoperate, and nothing more.

### 1.2 What the base protocol is not [#12-what-the-base-protocol-is-not]

The base protocol does not prescribe **what** data is shared or **with whom**. It carries no domain schema and no business rule. Two concerns sit outside this document and are referenced, not restated, here:

* **Domain taxonomies** define which data a field of work shares and what it means. They sit above the base layer as light, per-domain agreements. They are documented under `/protocols`, not here.
* **Exchange patterns** are reusable configuration templates for using the base protocol (one-to-many, broadcast, on-demand, request-response, cross-sector). They configure this protocol; they are not a layer of their own and carry no layer number. They are documented under `/patterns`, and each pattern descends by link to this specification.

A domain adding or changing a rule does not change the base layer, and a change to the base layer does not require a domain to change its taxonomy. This separation is what lets a single expensive-to-standardise layer carry many light agreements above it.

### 1.3 The organising principle: rebuildable by design [#13-the-organising-principle-rebuildable-by-design]

Neutrality is a checkable property. The normative core in Section 3 states what an interoperable implementation MUST do. The reference implementation in Section 5 is **one** way to satisfy that core. Conformance in Section 6 is defined against the published rules and test-vector suites, never against the reference implementation. Because every mechanism is drawn from open, published cryptographic primitives and open, numbered standards, any party can inspect the algorithms, implement them independently, and verify each record for itself. An organisation that wants to leave any particular implementation can build its own against these rules. In this version the same-network guarantee is a design guarantee; see Section 6 for what an implementation can build against before the settlement layer (PROV-1) and the test-vector suites are pinned.

### 1.4 External context [#14-external-context]

The design follows the position that shared infrastructure is better governed as an open protocol than as a platform a single party can withdraw (Masnick, "Protocols, Not Platforms", 2019). That reference is cited as context, not as a claim about this specification.

***

## 2. Terminology and conventions [#2-terminology-and-conventions]

### 2.1 Normative key words [#21-normative-key-words]

The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT, SHOULD, SHOULD NOT, RECOMMENDED, MAY, and OPTIONAL in this document are to be interpreted as described in RFC 2119 and RFC 8174, and only when they appear in capital letters.

### 2.2 Citation of open standards [#22-citation-of-open-standards]

Open, published standards are cited the way one cites an RFC: neutrally, as the published standard on which a mechanism rests and which any party may implement. This includes the open overlay standards for submit-and-lookup, topic naming and discovery, and peer authentication; an open key-derivation standard; canonical binary encoding (RFC 8949); and the open identity standards (W3C DID, W3C Verifiable Credentials, SD-JWT, OpenID4VP, OpenID4VCI, eIDAS). Where such a standard is cited, an implementer may follow the public standard directly; this document does not restate it.

### 2.3 Glossary [#23-glossary]

| Term                       | Definition                                                                                                                                                                                                                                                                                                          |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Party**                  | A legal entity that shares or receives data under the protocol, acting through one or more mandated actors.                                                                                                                                                                                                         |
| **Record**                 | A single, versioned, encrypted unit of shared data, encoded in a canonical wire format.                                                                                                                                                                                                                             |
| **Recorded action**        | The immutable statement that a party performed a named method with given arguments at a given time, from which state is reconstructed.                                                                                                                                                                              |
| **Envelope**               | The wrapping structure that carries a record's encrypted content, its signatures, and its metadata as typed tiers.                                                                                                                                                                                                  |
| **Field**                  | An independently encrypted and independently addressed unit inside a record.                                                                                                                                                                                                                                        |
| **Placement**              | The descriptor stating where each field's encrypted content lives (in the anchored record, in overlay storage, or in external storage).                                                                                                                                                                             |
| **The public audit layer** | The shared, append-only, tamper-evident record that no single party controls or can rewrite, to which every exchange is anchored.                                                                                                                                                                                   |
| **Anchor**                 | The commitment recorded on the public audit layer that binds a record to an ordered, tamper-evident position.                                                                                                                                                                                                       |
| **Anchor reference**       | The identifier by which a recorded action points to its anchor on the public audit layer.                                                                                                                                                                                                                           |
| **Proof**                  | A self-contained, independently verifiable demonstration that a record was anchored as claimed, requiring no trust in the anchoring operator.                                                                                                                                                                       |
| **Mandate**                | A scoped, time-bounded, revocable grant of authority for an actor to sign recorded actions on a party's behalf.                                                                                                                                                                                                     |
| **Delegation**             | The act of granting a mandate; itself a recorded action.                                                                                                                                                                                                                                                            |
| **Epoch**                  | A key-rotation interval; keys retire per epoch, and the transition is marked publicly.                                                                                                                                                                                                                              |
| **Register**               | The concept and specification by which a party publishes verifiable claims about itself to a known address for others to look up and verify.                                                                                                                                                                        |
| **Claim**                  | A signed, anchored statement a party publishes about itself, whose origin and integrity any counterparty can verify independently.                                                                                                                                                                                  |
| **Port contract**          | The interface a runtime component (the reader, writer, or recorder role; see Sections 3.5 and 5) MUST expose so that another party can interoperate with it. The MUST interfaces of these three roles are the port contracts; their published definitions are the interoperability surface referenced in Section 6. |

***

## 3. Normative core [#3-normative-core]

This section carries the rules an interoperable implementation MUST satisfy. Each subsection ends with its explicit conformance rules. Technical detail that is either not required for interoperability or is provisional pending technical review sits inside a collapsed technical-detail block, so that the normative body reads cleanly and a reviewer sees every provisional item at a glance. Provisional items are tagged inline as `[PROV-n]` and collected in Section 9.

The full normative text of the core is published in three sections, each pinned by date: [The record envelope and field placement](/protocols/data-sharing/v0.1/envelope), [Keys, identity and delegation](/protocols/data-sharing/v0.1/keys), and [Anchoring, addressing and retrieval](/protocols/data-sharing/v0.1/anchoring). The subsections below state the rules at the level an implementer plans against; where a subsection and its normative section differ in detail, the normative section governs. Deployment-specific strings (format identifiers, derivation namespaces, derivation labels, credential types) are not fixed by this specification: each deployment fixes and publishes its own deployment profile, and the normative sections show neutral, explicitly non-normative example values.

### 3.1 Data envelope and wire format [#31-data-envelope-and-wire-format]

A record is a versioned envelope of typed tiers, canonically encoded. The canonical encoding MUST be deterministic: the same logical record MUST produce the same bytes on any conforming implementation, so that two parties compute identical commitments and identical proofs. Canonical binary encoding follows RFC 8949.

A recorded action has a fixed shape. It carries:

1. an **identifier** for the action,
2. the **method** name it invokes,
3. the **arguments** to that method,
4. the **actor** identifier that signed it,
5. the **time** carried in the action itself, and
6. the **anchor reference** to its position on the public audit layer.

Method bodies read the time from the recorded action, never from a local clock, so that replay is deterministic (Section 3.5).

**Rules.**

* An implementation MUST encode records with the deterministic canonical encoding, such that two conforming encoders produce byte-identical output for the same logical record.
* An implementation MUST include an explicit version field in every record.
* An implementation MUST use the fixed recorded-action shape above, so that any party can reconstruct and replay an action it did not originate.
* An implementation MUST preserve canonical ordering of map and set structures on encode, and MUST NOT rely on any type distinction that the canonical encoding does not preserve.

<details>
  <summary>
    Technical detail
  </summary>

  The canonical-encoding profile is fixed by the `cbor-det-v1` test-vector suite (Section 6). The suite defines map-key ordering, the erasure of type distinctions the encoding does not preserve, and the byte-exact output an encoder MUST match. A rebuilder validates its encoder against the [published vectors](/protocols/data-sharing/v0.1/vectors) rather than against any prose here; the wire structure itself is specified in [The record envelope and field placement](/protocols/data-sharing/v0.1/envelope).
</details>

### 3.2 Addressing and discovery [#32-addressing-and-discovery]

Parties are addressed, and records are discovered, through the open overlay standards. Addressing rests on the open overlay submit-and-lookup standard; topic naming and discovery rest on the open overlay naming-and-discovery standards. These are open, published standards; an implementation follows them directly. Counterparty authentication is either the open peer-authentication standards or access control at the network boundary; both are conforming (Rules below).

The overlay is a routing fabric. It admits records into named topics and answers lookup queries. It does not hold state for the parties and does not need to be trusted for the integrity of a record, because integrity is established by the record's own signatures and its anchor (Sections 3.4 and 3.6). An overlay instance MAY be self-hosted, third-party operated, or both.

A service that chooses to be discoverable publishes its address on the shared infrastructure, and implementations resolve where to send by reading those records at call time. The reference deployment is designed private: it publishes no advertisement of its own and is configured with its endpoints directly.

**Rules.**

* An implementation MUST address records and admit them to topics using the open overlay submit-and-lookup standard.
* An implementation MUST support topic naming and discovery per the open overlay naming-and-discovery standards.
* Deployments authenticate counterparties either with the open peer-authentication standards or by controlling access at the network boundary (client certificates, address allowlists, or a private network); both are conforming. The reference implementation's data path uses network-boundary control; administrative surfaces adopt the open authentication standards.
* An implementation MUST NOT require any party to trust a specific overlay operator for the integrity of a record.

<details>
  <summary>
    Technical detail (provisional, pending technical review)
  </summary>

  **\[PROV-3 (1 of 2)]** Membership of any specific consortium overlay network, and the ownership boundary of a given overlay instance, are operator-tier configuration. They are out of scope for this specification: the base protocol fixes how addressing and discovery work over the open standards, not who operates a particular network or on what commercial terms. The consortium-membership and instance-ownership arrangements are proprietary and are not normative here.
</details>

### 3.3 Encryption principles [#33-encryption-principles]

Encryption is on by default and applied per field. Each field is encrypted independently and carries its own receivers, so that different parties can be granted access to different fields of the same record. Selective disclosure is achieved by granting a counterparty only the field keys it is entitled to. A field carries a **placement** descriptor stating where its encrypted content lives: inside the anchored record, in overlay storage, or in external storage. In every case the record carries a cryptographic commitment to the field, so a party can verify a field exists and is unchanged even without holding the key to read it.

Keys are derived, not stored. Every key an implementation needs, for a party's account, for a running instance, for a single record, for a single field, is derived on demand from a single master input plus a labelled context, through a five-level hierarchy. Derivation follows an open, published key-derivation standard. The hierarchy is built over two curves: secp256k1, which binds a runtime to the public audit layer, and P-256, which signs payloads in the formats that EU digital identity wallets and web identity systems already use. Both curves derive from the same master input, so an implementation covers audit-layer binding and EU wallet and web-identity signing without a second secret.

Keys retire per epoch. On rotation a new epoch begins, the transition is marked publicly and anchored, and data encrypted under a prior epoch stays decryptable to any party that held a key in that epoch. There is no re-encrypt-everything event.

The open cryptographic primitives on which these principles rest are HKDF, PBKDF2, AES-256-GCM, ECDH, and ES256. They are cited as the open basis; an implementer uses the published primitives.

**Rules.**

* An implementation MUST encrypt field content by default and MUST encrypt each field independently.
* An implementation MUST record a placement descriptor per field and MUST carry a cryptographic commitment to each field regardless of placement.
* An implementation MUST derive keys according to the open key-derivation standard, through the five-level hierarchy, over both curves.
* An implementation MUST mark and anchor epoch transitions so that any party can determine which epoch a record belongs to, and MUST keep prior-epoch data decryptable to prior-epoch key holders.
* An implementation MUST grant field access by wrapping only the keys for the fields a counterparty is entitled to, and MUST NOT require disclosure of a whole record to disclose one field.

<details>
  <summary>
    Technical detail (provisional, pending technical review)
  </summary>

  The exact construction (the derivation contexts, the parameters of the key-stretching and authenticated-encryption primitives, and the per-field content-key scheme) is fixed by the `dual-curve` and `docv2-envelope` test-vector suites (Section 6). A rebuilder matches the vectors once they are published (Section 6); the parameter values are not restated in this prose. Only the interop-load-bearing shape is normative here: five levels, two curves, open-standard key derivation, per-field independent encryption, per-epoch rotation.

  **\[PROV-2] Forward-secrecy trade-off.** The per-field content-encryption key is derived deterministically from the field's own content. This is what lets any party that legitimately holds a field's content rederive the key and verify the field independently, without contacting the party that recorded it. A deliberate consequence is that the scheme does not provide classical forward secrecy in the way an ephemeral-key transport does: determinism and independent verifiability are chosen over ephemerality. This is an engineering trade-off in favour of auditability and self-contained verification, not an oversight. The framing of this trade-off is subject to technical review.

  **\[PROV-3 (2 of 2)] Placement-channel ownership.** The placement descriptor semantics (selecting whether a field's content sits in the anchored record, in overlay storage, or in external storage) are normative and stated in the body above. The ownership boundary of overlay-versus-external storage, and who operates each store, are operator-tier configuration and are out of scope for this specification. This boundary is subject to technical review.
</details>

### 3.4 Anchoring to the public audit layer [#34-anchoring-to-the-public-audit-layer]

Every exchange is anchored to the public audit layer: a shared, append-only, tamper-evident record that no single party controls or can rewrite. The public audit layer is a shared, public network that any party may anchor to directly; no participant owns it or can gate access to it, which is what lets an anchored proof be verified by anyone and keeps the layer free of network-level lock-in. The anchor fixes an ordered, chained position for each recorded action, so that the sequence of a party's actions is unbroken and any gap or reordering is detectable.

**Rules.**

* An implementation MUST anchor every recorded action to the public audit layer as a chained, ordered entry.
* The anchor MUST carry a cryptographic commitment to the record's fields.
* A proof of anchoring MUST be independently verifiable, without trusting the operator that submitted the anchor.
* A cross-domain reference MUST carry its proof with it, so a party in another domain can verify the referenced record without access to the originating domain's storage.
* Each recorded action MUST derive a unique commitment key, so that no two actions collide on the audit layer.

<details>
  <summary>
    Technical detail (provisional, pending technical review)
  </summary>

  **\[PROV-1] Settlement-layer naming and anchoring mechanics.** This specification names the settlement layer only as "the public audit layer". The concrete script-level mechanics (carrying encrypted field bytes and commitments in spendable output data rather than in metadata-only outputs, the chaining container that links each action to the previous one, the self-verifiable inclusion proofs, and the per-action commitment-key derivation) are the interop-load-bearing detail and are fixed by the `utxo-chaining` and `cross-domain-refs` test-vector suites (Section 6). The naming of the underlying settlement layer, and the framing of the standards citations for these mechanics, are subject to technical review. A rebuilder verifies against the suites once they are published (Section 6).
</details>

### 3.5 Verification and replay semantics [#35-verification-and-replay-semantics]

An implementation reconstructs state by applying recorded actions in log order, and any two implementations applying the same actions in the same order MUST arrive at identical state. There is no master copy of state to be trusted; the log is the source of truth.

Method bodies are pure functions of state and the recorded action. They contain no clock read, no random draw, and no network call, so that replay is reproducible by construction.

An implementation checks itself. It replays recently applied actions and confirms that the result matches the state it holds. A disagreement (drift) signals tampering, a non-deterministic method body, or a corrupt storage layer, any one of which is grounds to stop.

Method bodies evolve by version. Each recorded action carries the method version it was recorded with, and replay applies that version. A migration is itself a recorded action, so schema evolution happens by explicit cutover and never silently changes the meaning of a past action.

The runtime contract is expressed as three roles: a **reader** that admits recorded actions from the audit layer and replays them, a **writer** that encodes, signs, and submits actions, and a **recorder** that persists canonical state and verifies replay determinism.

**Rules.**

* An implementation MUST reconstruct state deterministically by applying recorded actions in log order.
* Method bodies MUST be pure functions of (state, recorded action) and MUST NOT read a clock, draw randomness, or make a network call.
* An implementation MUST detect drift between reconstructed and stored state and MUST halt or raise on drift.
* Each recorded action MUST carry the method version it was recorded with, and replay MUST apply that version.
* A schema change MUST be introduced as a recorded cutover action, not as an untracked change.

### 3.6 Identity and delegation [#36-identity-and-delegation]

Authority binds through a verifiable chain of grants: a legal entity to a runtime account, an account to a mandated actor, and an actor to each signed recorded action. Every link is verifiable, and none of them requires a network call at the moment an action is recorded.

A mandate grants a natural person or a service scoped, time-bounded authority to sign actions on an account's behalf. The actor's public key is pinned at the moment the mandate is granted. Verification is therefore local: an action's signature verifies against the key pinned at grant time, with no lookup on the critical path. A delegation and its revocation are themselves recorded actions on the audit layer, so the authority history is auditable.

Because every key in the chain is a distinct per-context derivation, compromise at one link does not cascade: a leaked action-signing key reveals nothing about the mandate, and a compromised mandate can be revoked in its own scope without touching the account.

Identity binds to the open standards. Accounts and mandates bind to W3C DID and W3C Verifiable Credentials; citizen-facing mandates MAY be issued as portable, selectively disclosable credentials using SD-JWT and presented over OpenID4VP and OpenID4VCI; binding aligns with eIDAS. The credential is optional; organisational flows work without it.

**Rules.**

* An implementation MUST verify each recorded action's signature against the actor public key pinned at grant time, locally, with no network call at the moment of recording.
* A mandate MUST be scoped, time-bounded, and revocable.
* A delegation and its revocation MUST each be recorded actions anchored to the public audit layer.
* An implementation MUST reject an action from an actor without an active, in-scope mandate for the method invoked.
* An implementation SHOULD bind accounts and mandates to the open W3C DID and Verifiable Credentials standards, and MAY accept portable credentials per SD-JWT and OpenID4VP/OpenID4VCI for citizen-facing flows.

<details>
  <summary>
    Technical detail (provisional, pending technical review)
  </summary>

  **\[PROV-4] Data-protection erasable-mandate pattern.** An append-only record cannot delete a past entry, which appears to conflict with a data-subject erasure request. The protocol resolves this with a separable identity link: the runtime operates on a pseudonymous actor identifier, and the mapping from that pseudonymous identifier to a natural person is held as a separate, erasable link. Erasing the link renders the person no longer identifiable from the append-only record, honouring an erasure request without rewriting history. The pattern is normative; the concrete operator-owned identity-link mechanism that stores and erases the link is proprietary operator configuration and is out of scope for this specification. The split is subject to technical review.
</details>

***

## 4. Register and discovery standard [#4-register-and-discovery-standard]

The register lets any organisation publish verifiable claims about itself to a known address, so that any counterparty can look those claims up directly and verify their origin and integrity for itself, with no central gatekeeper. A claim is a signed, anchored recorded action; the signature is checkable by anyone. Publishing is one-to-many; verifying is many-to-one.

The register is itself an application of the base protocol, not a new layer. It reuses the identity and delegation rules of Section 3.6 to bind a claim to its issuer, the anchoring rules of Section 3.4 to make a claim tamper-evident, and the addressing rules of Section 3.2 to make a claim discoverable. A continuous stream of verifiable updates replaces a periodic manual exercise: a party publishes an update, and counterparties verify it independently whenever they need it.

**Rules.**

* A claim MUST be a signed recorded action anchored to the public audit layer.
* A claim MUST carry its issuer binding, so that any party can verify the claim's origin against the issuer's pinned key.
* Verification of a claim MUST be independent of any central party.
* A published claim MUST be discoverable through the open addressing and discovery standards of Section 3.2.

**Scope of this version.** The register is specified here as a concept and specification. This version defines no live lookup service, no directory user interface, and no adopter list. No branded instance of the register is named or implied by this specification; any party may operate its own instance over the same rules and the same public audit layer.

***

## 5. Reference implementation [#5-reference-implementation]

A reference implementation, including the state machines that run the protocol, is licensed source-available under the Business Source License 1.1 (text on the [licence page](/licence)), with each version converting to the Apache-2.0 open-source licence two years after its release; self-hosting is free for everyone under the licence's additional use grant, so it is free to fork and free to run. It exists to demonstrate one working way to satisfy the normative core, and it is explicitly **not** the standard: conformance (Section 6) is defined against the public rules and the published test-vector suites, and any language may implement the standard.

The reference architecture expresses the runtime contract of Section 3.5 as replaceable adapters: a reader, a writer, and a recorder, around locally owned state and pure method bodies. A **topology** is an adapter swap over the same code path:

* **Full**: reads and writes; a normal runtime that both submits and consumes.
* **Query replica**: reads only; a read-only mirror that scales out queries.
* **Ingest-only**: writes only; a submit-only worker.
* **Observer**: neither reads nor writes into state; an audit-only viewer that sees only what it has been keyed for.

Selecting a topology is a configuration of the same reference architecture, not a different protocol.

**Rules.**

* An implementation MAY reuse, fork, or replace the reference implementation in whole or in part.
* An implementation MUST NOT depend on the reference implementation to claim conformance; conformance is against the rules and suites only.
* An implementation MAY adopt any topology above, since a topology is an adapter configuration and does not change the wire behaviour other parties observe.

Operator-infrastructure detail (provisioning, hosting, key-management-service or hardware-module setup, funding, custody topology, and runbooks) is out of scope for this specification. A topology is an adapter swap; how an operator runs and scales it is not part of the base protocol.

***

## 6. Conformance [#6-conformance]

An implementation is interoperable when it demonstrates the following. Each item maps to a rule in Sections 3 and 4 and to a published test-vector suite where one applies. The suites are named here; their vector values are not embedded in this document. A rebuilder fetches the vector suites (the first are [published](/protocols/data-sharing/v0.1/vectors); the rest follow alongside the reference implementation, see "How to build against this specification" below) and validates against them.

| #  | An implementation MUST demonstrate                                                                             | Maps to | Test-vector suite        |
| -- | -------------------------------------------------------------------------------------------------------------- | ------- | ------------------------ |
| 1  | Deterministic canonical encoding of records                                                                    | 3.1     | `cbor-det-v1`            |
| 2  | The versioned typed-tier envelope and recorded-action shape                                                    | 3.1     | `docv2-envelope`         |
| 3  | Five-level, dual-curve key derivation per the open key-derivation standard                                     | 3.3     | `dual-curve`             |
| 4  | Correct resolution of the per-field placement descriptor                                                       | 3.3     | `placement`              |
| 5  | Chained, ordered anchoring with independently verifiable proofs                                                | 3.4     | `utxo-chaining`          |
| 6  | Overlay-based addressing, admission, and discovery                                                             | 3.2     | `overlay-binding`        |
| 7  | Cross-domain references that carry their own proof                                                             | 3.4     | `cross-domain-refs`      |
| 8  | Deterministic replay and drift detection                                                                       | 3.5     | (behavioural, see below) |
| 9  | Local delegation verification against a pinned key, with recorded revocation                                   | 3.6     | (behavioural, see below) |
| 10 | Implementation of the published port contracts (the MUST interfaces of the reader, writer, and recorder roles) | 3.5, 5  | (interface contracts)    |

Items 8 and 9 are behavioural: an implementation demonstrates them by exhibiting the required behaviour, not by matching a fixed byte vector. Item 10 requires implementing the published port-contract interfaces (the MUST interfaces of the reader, writer, and recorder roles of Sections 3.5 and 5, defined in the glossary) that define the interoperability surface.

**Interoperability test.** Two independent implementations are interoperable when they:

1. reconstruct identical state from the same ordered log,
2. verify each other's records without trusting the other's storage, and
3. anchor to the same public audit layer.

**Conformance levels.** A MUST rule is required for core interoperability. A SHOULD rule is recommended and its absence must be justified. A MAY rule is optional. An implementation states which SHOULD and MAY provisions it supports.

**How to build against this specification.** The `cbor-det-v1` suite (item 1) and the `historical-float64-decode` decode-tolerance suite are published at [`/protocols/data-sharing/v0.1/vectors`](/protocols/data-sharing/v0.1/vectors). The remaining suites named above and the port-contract interfaces of item 10 follow alongside the reference implementation, at the same address and at `/protocols/data-sharing/v0.1/interfaces`. A rebuilder starts there: fetch the suites, implement the MUST interfaces of the reader, writer, and recorder roles, and validate byte-exact output against the vectors. Until each suite is published, the normative sections fix the shape an implementation must match; the published vectors pin the bytes.

***

## 7. Governance [#7-governance]

No single party owns this standard, can change its normative core, or can withdraw it. Four mechanisms are designed to make that true and verifiable; the licence that anchors them is published on the [licence page](/licence).

**Licence.** The protocol and its specifications are published under an open, royalty-free licence with a patent non-assertion covenant; the reference implementation, including its state machines, is licensed source-available under the Business Source License 1.1, which converts to the Apache-2.0 open-source licence two years after each version's release and grants free self-hosting to everyone, governments included. There is no registration requirement and no fee for implementing or self-hosting. Anyone is free to implement, fork, and run them. The licence exists to make neutrality verifiable in practice rather than dependent on a commercial relationship.

**Public working group.** The standard is developed in public, and anyone can join the working group: organisations, implementers, and domain experts who review the specification, propose changes, or help define taxonomies. The normative core cannot be changed unilaterally, and there is no central gatekeeper.

**Separation of specification from implementation.** The normative core is separate from any reference implementation. The specification cannot be changed by one party acting alone, and no implementation is privileged in defining conformance.

**Hand-over clause.** Stewardship passes to the working group once at least three parties are actively implementing the protocol, participating in working-group discussions, and ratifying taxonomy changes. That clause was part of the governance model from the start, not added afterwards. This version does not claim an independent foundation, committee, or not-for-profit body; neutrality in this version rests on the open working group, the specification-implementation separation, the built-in transfer clause, and the open royalty-free licence.

**Initiator and first maintainer.** mintBlue initiated this standard and wrote the first specifications. The initiator is not the owner: the maintainer role is temporary and transferable, and the credit records origin, not control. The current role is practical stewardship, keeping the first version coherent and preparing the work for transfer as participation grows.

**Versions and forks.** Versions are explicit, so parties always know which agreement an exchange follows, and nobody is upgraded on someone else's timetable. Because everything is open, anyone who disagrees with a choice can fork a taxonomy or the specification itself, and a fork carries exactly as far as others choose to adopt it. A fork has one natural boundary: the public audit layer. As long as every party keeps anchoring to the same audit layer, every exchange stays verifiable across versions and forks. Splitting the record itself is the one move that breaks this.

**Open and paid.** Everything needed to build, host, and operate an interoperable implementation is source-available and free to self-host. An organisation can run the full stack itself, commission an implementation from another party, or test compatibility against the public rules, with no licence fee for self-hosting and no required integration with any managed service. The one case the reference implementation's licence prices is operating it as a hosted service for third parties; those terms are public and identical for every licensee (see the [licence page](/licence)). The paid route is managed provisioning: a provider operates an implementation for organisations that do not want to run the infrastructure themselves, with one-click set-up, operational scale, and service-level commitments. Any conforming provider can offer this; the initiator is simply the first to do so. Paying for provisioning buys no control over the specification and no permission to participate. The full governance model, licence, and hand-over conditions are documented at `/governance`.

***

## 8. Versioning and changelog [#8-versioning-and-changelog]

This is version **0.1**, status **Draft, pending technical review**. The base layer is deliberately minimal and is versioned explicitly.

Future versions are proposed and ratified through the public working group. The normative core cannot change unilaterally: a change to a MUST rule requires working-group ratification, and versions remain explicit so that adopters choose when to move.

### Changelog [#changelog]

* **v0.1, revision of 2026-09-01.** Publishes the normative sections in full ([The record envelope and field placement](/protocols/data-sharing/v0.1/envelope), [Keys, identity and delegation](/protocols/data-sharing/v0.1/keys), [Anchoring, addressing and retrieval](/protocols/data-sharing/v0.1/anchoring)) and the first test-vector suites (`cbor-det-v1`, `historical-float64-decode`; see [Test vectors](/protocols/data-sharing/v0.1/vectors)). Introduces deployment profiles: the specification no longer fixes deployment-specific strings; each deployment fixes and publishes its own. Widens the peer-authentication rule of Section 3.2 to admit network-boundary control as conforming, and adds the discovery rule. Links the published licences (Section 7).
* **v0.1 (2026-07-17)** Initial specification. Establishes the normative core (envelope and wire format, addressing and discovery, encryption principles, anchoring to the public audit layer, verification and replay, identity and delegation), the register-and-discovery chapter, the reference-implementation reference, the conformance requirements, and the governance model. Four items are marked provisional pending technical review (Section 9).

***

## 9. Provisional-items register [#9-provisional-items-register]

The following four items are the only content in this specification pending technical review. Each is written inside a collapsed technical-detail block at its point of use and tagged inline. Content from the internal threat model and the internal privacy analysis is **excluded** from this version, not deferred: it does not appear here in any form.

| Item       | Topic                                                                     | Provisional because                                                                                                               | Handling in this version                                                                                                                               |
| ---------- | ------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **PROV-1** | Settlement-layer naming and anchoring mechanics (Section 3.4)             | The naming of the underlying settlement layer and the framing of its standards citations are a strategy and technical-review call | The layer is named only "the public audit layer"; the script-level mechanics sit in a technical-detail block and are fixed by named test-vector suites |
| **PROV-2** | Forward-secrecy trade-off (Section 3.3)                                   | The framing of a deliberate cryptographic trade-off is subject to technical sign-off                                              | Written as an engineering trade-off in favour of determinism and independent verifiability, never as a shortcoming                                     |
| **PROV-3** | Placement-channel ownership and consortium membership (Sections 3.2, 3.3) | The ownership and operator boundary is operator-tier configuration                                                                | Descriptor semantics are normative in the body; ownership and consortium membership are out of scope                                                   |
| **PROV-4** | Data-protection erasable-mandate pattern (Section 3.6)                    | The concrete operator-owned identity-link mechanism is proprietary                                                                | The erasable-mandate pattern is normative; the operator-owned link mechanism is out of scope                                                           |
