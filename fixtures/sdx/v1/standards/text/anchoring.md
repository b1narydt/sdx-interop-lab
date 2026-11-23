<!-- tpnil:provenance-header -->
**TPNIL pinned source text.** SDX Protocol specification v0.1, dated 2026-07-17, revised 2026-09-01; keys, envelope and anchoring ratified 2026-09-01. This file holds the page *Anchoring, addressing and retrieval*, a normative section ratified on 2026-09-01. Requirement citations use the clause prefix `ANC`.

- Source page: <https://sdxprotocol.org/protocols/data-sharing/v0.1/anchoring/>
- Retrieved from: <https://sdxprotocol.org/llms.mdx/protocols/data-sharing/v0.1/anchoring.md>, the site's Markdown rendition of the source page
- Retrieved at: 2026-11-11T05:08:32Z
- SHA-256 of the retrieved bytes: `ba8e503e541c09f6fad78fb6838311014fbe617a5c6ab74e718e7983fb871eda`
- Licence: SDX specification texts and test vectors licence, Version 1.0, 1 September 2026, Licensor mintBlue B.V. [Reference copy](../../../../../LICENSES/SDX-Specification-License-1.0.reference.txt)
- Modification: none. The retrieved bytes follow the closing marker of this header unchanged; TPNIL added only this header. Root-relative links in the text resolve against `https://sdxprotocol.org`.

Attribution: SDX Protocol specification, version 0.1 (2026-07-17, revised 2026-09-01). The source page is the canonical publication. This copy retains the SDX licence terms and is excluded from TPNIL's Apache-2.0 grant; see the [third-party notices](../../../../../THIRD_PARTY_NOTICES.md).
<!-- tpnil:upstream-text-follows -->
# Anchoring, addressing and retrieval (/protocols/data-sharing/v0.1/anchoring)



> Normative. Reflects the specification as ratified on 1 September 2026. Version pinning is by date. Where this text and a published test vector disagree, the vector wins and the text is corrected.

## Anchoring and the audit log [#anchoring-and-the-audit-log]

The audit layer is a public, append-only settlement network. Each recorded action is committed into a spendable entry on that network; entries chain, so every action references its predecessor and any reader can walk the chain. A record carries its own inclusion proof, so verifying it needs only the record and the network's public headers, not the cooperation of whoever wrote it.

This section specifies the container the record travels in, the key that binds a record to the action it claims to be, the rule that links each action to its predecessor, and what a verifier must do and must hold in order to check any of it.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted as described in RFC 2119.

### 1. Why records live in spendable entries [#1-why-records-live-in-spendable-entries]

A settlement network offers two places to put data. One is a metadata-only output, which the network marks permanently unspendable and which therefore cannot be referenced by any later entry. The other is an ordinary spendable entry, whose spending condition can carry arbitrary data alongside the condition itself.

This specification requires the second, and forbids the first for action data. The reason is ordering. Sequence in this protocol is not asserted by a coordinator or inferred from timestamps; it is enforced by the network's own double-spend rule. Each new action spends the entry its predecessor left behind, so the network itself refuses to admit two actions claiming the same position. An unspendable output cannot be spent, so it cannot carry that guarantee, and a design that put the record in an unspendable output would need a separate ordering mechanism with separate failure modes.

Two consequences follow and are accepted rather than hidden.

* A spendable entry costs slightly more bytes than an unspendable one, because the spending condition sits alongside the data.
* Each action consumes and re-creates a small value. Implementations MUST fund this; the cost is per action, not per byte.

Placing the record in a spendable entry also buys spend control. The entry can only be consumed by whoever can satisfy its spending condition, which by construction is the participant whose chain it belongs to. No third party can interrupt a chain by consuming its tip.

### 2. The chaining container [#2-the-chaining-container]

#### 2.1 Canonical shape [#21-canonical-shape]

Every action-carrying entry MUST use the following spending condition, in this order:

```
<record-bytes> DROP <commitment-key> CHECKSIG
```

The record bytes are pushed onto the evaluation stack and immediately discarded, leaving an ordinary single-key signature check. So the entry is a normal, relayable payment to a single key that happens to carry a payload, and the payload imposes no evaluation cost on the network.

* `<record-bytes>` are the canonical binary encoding of the record envelope. The envelope format is specified in *The record envelope*; this section treats it as an opaque byte string with a readable header.
* The push MUST use the minimal opcode for the payload size. Implementations MUST NOT hand-assemble these conditions; encoders that select minimal encoding automatically are the required path, because a non-minimal push produces a byte-different condition for identical content and breaks digest comparison.
* `<commitment-key>` is the per-record commitment key defined in section 3.

#### 2.2 One data field [#22-one-data-field]

A conforming record occupies exactly one data field. A verifier MUST reject an entry carrying zero fields or more than one, and MUST NOT attempt to reassemble a record from several fields.

Multi-field carriage is reserved. It is the escape path for records that exceed the size budget of section 8 after externalisation has been exhausted, and it is not part of this version. An implementation that meets an oversized record MUST fail the write with a stated size error rather than improvise a split.

#### 2.3 Position is not the anchor [#23-position-is-not-the-anchor]

Neither the input that consumes the predecessor nor the output that carries the new record is pinned to a fixed position. A writer chooses positions deterministically; a reader locates the chain-relevant input and output by scanning and matching, not by index.

* To find the successor entry, a reader decodes each output of the consuming transaction and keeps the one whose commitment key matches the expected derivation for the record that output declares.
* To confirm continuity, a reader scans the inputs for the one consuming the recorded chain tip.

Position-independence is deliberate. Pinning the chain to position zero made every entry of a chain identifiable to any observer holding a single identifier, because the spend edge could be walked forwards and backwards from that one point regardless of how the keys were derived. Removing the position invariant removes that free correlation, and it is the derivation match of section 6.2, not an index, that establishes what belongs to a chain.

#### 2.4 Value [#24-value]

The entry MUST carry a value at or above the network's minimum relayable amount. The default is one unit of the network's smallest denomination. Deployments MAY configure a higher floor to simplify housekeeping, and implementations MUST expose that floor as configuration rather than a constant.

### 3. The per-record commitment key [#3-the-per-record-commitment-key]

#### 3.1 Derivation [#31-derivation]

The key in the spending condition is derived per record, never reused. It is the signing key for that one action, taken from the hierarchy specified in *Keys and derivation*, using:

* the signing protocol scope defined there, not a separate scope of its own;
* a key identifier naming the account, the chain and the action, in the grammar that section fixes;
* the participant itself as counterparty, so the key is a self-derivation;
* the key tree of the epoch active at the moment of writing.

There is no separate protocol scope for commitment keys. The cryptographic operation is identical to ordinary record signing at the same level of the hierarchy, and introducing a distinct scope would fragment the derivation model for no gain.

#### 3.2 Why the key rotates per record [#32-why-the-key-rotates-per-record]

Three properties depend on it.

**Blast radius.** A leaked signature exposes at most the private key for that one record's derivation. Every later entry uses a different derivation under the same root, so an attacker holding one leaked key cannot consume any subsequent tip. Only compromise of the root itself does that.

**Consistency.** Per-record encryption keys and per-record signing keys already rotate this way. A static key in the spending condition would have been the weakest link in an otherwise uniform model.

**Correlation resistance, qualified.** An observer sees a sequence of unrelated keys rather than one recurring identity key, so keys alone do not cluster a chain. This is a real but partial property, and section 9 states exactly what it does not close.

#### 3.3 Determinism is required [#33-determinism-is-required]

The commitment key MUST be a deterministic function of the root and the action identifier. A randomised or ephemeral per-record key is non-conforming, even though it would give the same unlinkability, because a verifier could then no longer derive the expected key independently. Replay verification depends on the verifier recomputing what the writer must have used, without the writer communicating anything out of band.

#### 3.4 Scope of the self-derivation rule [#34-scope-of-the-self-derivation-rule]

The self-counterparty rule governs the chain tip and the input that consumes it. It does not govern:

* entries a participant addresses to another party, which are derived under a distinct delivery scope with the recipient as counterparty so that only the recipient can consume them;
* fee and change outputs, which belong to the funding layer and follow its own conventions.

### 4. Chaining rules [#4-chaining-rules]

#### 4.1 First action [#41-first-action]

The first action on a chain has no predecessor. It consumes a funding entry the operator provides, and it carries a distinguishing marker in its envelope header identifying it as the origin action. Its own output is committed under the same per-record derivation as every later action.

Origin uniqueness is NOT enforced at admission. Anyone able to satisfy a topic's submission rules can publish an entry carrying an origin marker for any chain identifier. This is not the exposure it first appears to be:

* a participant recognises its own origin action from its own local record, established when the chain was created, and ignores any competing marker;
* a consumer following a chain does so from an origin identifier the operator published out of band, so markers elsewhere in a topic are irrelevant to it.

Operators MAY add a topic rule rejecting duplicate origin markers to reduce noise. That is deployment configuration and MUST NOT be relied on as a protocol guarantee.

#### 4.2 Every subsequent action [#42-every-subsequent-action]

Exactly one input of a non-origin, non-rotation action MUST consume the chain's current tip. Position is unconstrained; count is not. Two inputs consuming tips, or none, is a malformed action.

Only one action per chain may be in flight at a time. A writer MUST serialise its own writes. An implementation that observes more than one spendable tip for its own chain MUST halt with a validation error rather than guess: that state means either a concurrent write in violation of this rule, or stale local state, and both are corrected by an operator rather than by picking one.

Writers track their own tip locally, together with the predecessor's action identifier and key epoch, so that the key needed to sign the consuming input can be resolved without a second lookup.

#### 4.3 Rotation [#43-rotation]

A rotation action moves control of the chain from one root to the next. Both roots are in play for exactly one action:

* the input consuming the tip is signed under the OLD root, at the predecessor's derivation path;
* the new output is committed under the NEW root, at the rotation action's own path;
* the record envelope carries two signatures, one under each root, binding intent to effective control.

The transfer of control is automatic rather than announced. Because the commitment key is a function of (root, action identifier), and rotation changes the root, only the holder of the new root can derive the key that consumes the rotation action's output. A compromised old root cannot fork the chain past the rotation point. It can still derive keys for historical actions under its own paths, which is what makes the rotation action itself signable, and what lets an archived root release any entry left unconsumed at the boundary.

Everything the rotation action emits moves to the new root, including any entries it addresses to other parties. There is no partial migration.

A verifier walking across a rotation needs nothing special. Every action, in every epoch, still consumes the immediately preceding tip.

### 5. Writing a record [#5-writing-a-record]

#### 5.1 Ordering of the write (normative) [#51-ordering-of-the-write-normative]

The submission to the settlement network MUST come LAST, after every step that can still refuse the write, and a refused submission MUST be reported as a failure.

This is not a preference about latency. A writer that broadcasts first has already spent its own funding entries by the time admission is checked, so a caller told the operation failed cannot safely retry: the money is gone on a write the implementation reported as not having happened. The conforming order is: build the action without sending, submit for admission, assert admission, and only then release the built action to the network.

Four consequences follow, and each is a way to get the ordering wrong while appearing correct. They are listed rather than counted, deliberately: a count in the prose is a second place to update, and it is the place that goes stale.

* On the legs where admission did NOT take the transaction, the caller MUST release the inputs its built action reserved. Without that, the retry this rule exists to make safe finds its own funds locked behind the attempt that just failed.
* On the leg where admission DID take the transaction, the caller MUST NOT release. The transaction may reach the network regardless of what the send reported, and recording a spend as failed when it then happens is a worse record than an unsent one an operator can see and resolve.
* A refused broadcast is REPORTED, not raised. A send that answers with a per-transaction status rather than an exception will return a refusal as a successful call. The caller MUST match the reported status against its own transaction identifier and accept only the statuses that mean sent or pending.
* Where the release ITSELF fails, and where the outcome is undetermined, the caller MUST report each as an outcome distinguishable from an ordinary failure. Section 5.2 states why.

#### 5.2 Three outcomes, not one [#52-three-outcomes-not-one]

A caller that treats every unhappy path as one failure will lose funds on two of them. A conforming implementation reports three:

| Outcome         | What is true                                                                                             | What the caller must do                                                                                                                                                  |
| --------------- | -------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Failed          | Nothing was sent and the reserved inputs were released.                                                  | Retry is safe.                                                                                                                                                           |
| Inputs retained | Nothing was sent, but releasing the reservation did not work.                                            | MUST NOT retry. Releasing is now an operator action out of band. Nothing was spent; the harm is a stranded reservation, and that distinction is what the caller is owed. |
| Undetermined    | Admission took the transaction, so it may still confirm, and the built action has already been released. | MUST NOT retry. Reconcile by checking the network for the transaction identifier, which this outcome MUST carry.                                                         |

Reporting the third case as an ordinary failure is the one that costs money: a caller COMPLYING WITH THIS SPECIFICATION would fund a second attempt while the first may still confirm, which is exactly the double spend the ordering exists to prevent, arriving through the single leg the ordering cannot cover.

The transaction identifier on the undetermined outcome is a deliberate, narrow exception to the rule that failures carry no payload. That rule exists because a dependency's error text can quote credentials and internal paths. A transaction identifier is not error text: it is the caller's own output, computed and validated before the send was attempted, and a public network identifier the moment the transaction is mined. Every other failure stays payload-free, and an implementation MUST NOT read this as licence to attach payloads to failures at large.

#### 5.3 Ancestry for an unproven predecessor [#53-ancestry-for-an-unproven-predecessor]

A writer chains onto its own predecessor without waiting for that predecessor to be mined. To do so it MUST supply the predecessor's proof ancestry alongside the input that consumes it. An implementation that consumes its own tip without supplying ancestry fails on every write after the first, because the validating layer finds no proof context for the input and refuses it.

The scope of what a writer can supply is stated rather than left to be discovered. The ancestry a writer assembles from its own chain covers its own tip and nothing else. Two other classes of input are NOT covered by it and remain the responsibility of a future contract: inputs consuming an entry another participant addressed to this one, and fee inputs drawn from a shared funding pool.

#### 5.4 Header verification on the write path [#54-header-verification-on-the-write-path]

Supplying that ancestry makes the validating layer verify merkle roots on the main write path. Whose infrastructure answers that query is a deployment decision this specification constrains, because a naive answer makes every write depend on a third party's uptime.

An implementation MUST satisfy all four of the following.

1. **A header-lookup failure MUST NOT be reported as an invalid record.** The natural failure path turns an unreachable header source into an invalid-input error, and an operator reading that will investigate a transaction that is not at fault. The failure must be distinguishable at the boundary.
2. **There MUST be a fallback when the configured header source is unavailable.** Degrading to a public header source is acceptable and is strictly better than refusing to write. Degrading to "the participant stops writing" is not. Which fallback, and whether it is per-deployment configurable, is an implementation decision; the absence of any fallback is not.
3. **Header results MUST be cached across writes.** Consecutive writes chain onto the same mined ancestor, so the steady state is roughly one lookup per new block, not two per write.
4. **None of the above may introduce a confirmation requirement.** The header being looked up belongs to a mined ancestor, never to the tip being consumed. A degraded or unavailable header source MUST NOT be resolved by waiting for the tip to be mined.

#### 5.5 Proof acquisition is a named responsibility [#55-proof-acquisition-is-a-named-responsibility]

An implementation MUST run a process that acquires inclusion proofs for its own written transactions and rebroadcasts those not yet accepted, and MUST name the component that owns starting and stopping it.

This is stated as an obligation because its absence is not a missing feature but a slowly fatal one, and it presents as something else. Every write consumes the previous write's output, so with no proof ever acquired the unproven ancestor depth grows until the writer can no longer assemble verifiable ancestry and writes fail outright. A fresh local database resets the depth. The failure therefore presents as "works for days, then dies" rather than as an absent component, which is why naming the owner is part of the specification.

Four requirements follow from that ownership.

* The storage the process reads through MUST be attached before it starts, and MUST NOT be released before it stops.
* Stopping MUST NOT wait out an inter-pass sleep, whether the vendor's or the implementation's own. Once asked to stop, no further pass can begin; waiting for a loop to exit adds its sleep to every shutdown without making teardown safer. This binds any deferred-start retry the implementation adds, not only the loop itself.
* The process MUST NOT be started when no verifiable header source is installed, and the refusal MUST be reported exactly once. Its header task runs on every pass, so with no source that can answer it fails on every pass. Observed on a live deployment, that produced a continuous retry storm which delayed a commit by minutes and buried the single line naming the real fault under thousands of identical ones. Starting in that state is worse than not starting, and a participant that refuses on this ground still serves reads and writes; it simply does not pretend to acquire proofs.
* A process that fails to start, or whose loop dies, MUST NOT fail the boot. Serving reads and writes without it is strictly better than refusing to start. The failure MUST be reported rather than swallowed.

### 6. Verifying a record [#6-verifying-a-record]

#### 6.1 Self-verifiable inclusion proofs [#61-self-verifiable-inclusion-proofs]

A record cites and carries what a verifier needs. When one action references another, the reference embeds a compact encoding of the referenced transaction together with its merkle path.

Verification is therefore offline with respect to the writer. It needs:

* the record itself, including the embedded proof;
* a source of the network's block headers that the verifier controls.

It does not need a live query to the referenced participant, its node, or any index. Note what the proof does and does not carry: it carries the transaction and its merkle path, but NOT the headers. The verifier resolves the merkle root against its own header source, which is what makes the check a statement about the canonical chain rather than a statement about whoever supplied the proof.

A verifier MUST, for each reference:

1. parse the proof into a transaction and a merkle path;
2. compute the merkle root the path resolves to;
3. confirm that root against its own header source; a failure means either the range is unknown to this verifier, which is a configuration fault, or the proof names a non-canonical chain, which is an attack;
4. confirm the cited transaction identifier equals the identifier computed from the supplied transaction bytes;
5. confirm the cited output index names an output that exists in that transaction and has the container shape of section 2.

A verifier that is also a confidentiality-layer recipient of the referenced record SHOULD additionally decode it and confirm that its header declares the chain and action the citation claims. This is the honest-citation guard: without it, a dishonest citer can point at any valid transaction and label it as anything, and a verifier can confirm only that some valid transaction exists at that position. For high-stakes citations, the citer MUST be added as a recipient of the referenced record so that this check can run.

Any failure across the reference set dead-letters the WHOLE citing action. A partially verified action MUST NOT be dispatched.

A practical note on retention: the proof anchors to a header that must be in the verifier's cache at the moment of verification. Where a write and its verification may be separated by years, the verifier's header coverage must extend back far enough. Operators maintain headers from the network's origin; this is ordinary infrastructure, not a protocol concern.

#### 6.2 The chain-integrity check [#62-the-chain-integrity-check]

This is the check that binds an entry to the chain it claims to belong to. A verifier MUST:

1. decode the entry's spending condition into its commitment key and its data fields;
2. assert exactly one data field;
3. read the record's plaintext header to obtain the action identifier and the key epoch it declares;
4. derive the expected commitment key for that action identifier under the root for that epoch;
5. compare the key in the spending condition to the derived key, byte for byte.

A mismatch dead-letters the record with reason `integrity-fail`.

What this defeats is substitution. Without it, an attacker could lift a valid record and place it in a differently committed entry, and every signature inside would still verify. Binding the on-chain key to the record's own declared identity and epoch closes that, and it does so by recomputation rather than by trusting a stored index: no registry lookup is involved, so a missing bookkeeping row is an audit-trail gap and never a correctness gap.

**The scope of this check is limited and the limit is normative.** Step 3 requires reading the plaintext header, which requires decrypting the record's outer confidentiality layer. Only parties holding a recipient key for that layer can perform it. Concretely:

* a participant's own reader is always a recipient of its own records and MUST perform the check;
* readers added as recipients by a consortium MUST perform it;
* observers holding no recipient key CANNOT perform it. They get what the settlement network guarantees, which is that a valid spend was authorised by whoever held the commitment key, and nothing about whether the payload is the one that key was derived for.

An observer that requires envelope-substitution detection MUST be added to the record's recipient list. There is no weaker path to the same guarantee, and an implementation MUST NOT present admission by a node as a substitute for it.

### 7. Walking the chain and replay [#7-walking-the-chain-and-replay]

#### 7.1 The walk [#71-the-walk]

Starting from the origin entry, or from the entry of the last processed action, a reader repeats:

1. find the transaction that consumes the current entry;
2. for each of its outputs, attempt to decode the container of section 2 and, where it decodes, derive the expected commitment key for the record it carries;
3. keep the output whose key matches; that is the successor;
4. if no output matches, the record dead-letters as `integrity-fail`;
5. set the current entry to the matched output and repeat.

Where a transaction carries exactly one conforming entry, this reduces to the obvious walk. The scan-and-match form is what makes the walk correct once a transaction may carry several.

#### 7.2 Canonical order [#72-canonical-order]

Canonical order is spend order. It is the only ordering this specification recognises.

Block height is NOT the ordering axis. Two actions in the same block are ordered by their spend relationship: one action's input consumes the other's output, and that is the whole of it. An implementation MUST NOT reorder by timestamp, by height, or by arrival.

#### 7.3 Replay determinism [#73-replay-determinism]

Replaying a chain from any point MUST produce the same result as the original processing, given the same inputs. Three rules make that true, and each is load-bearing:

* Keys are deterministic (section 3.3), so a replayer derives what the writer used.
* Cited proofs travel inside the record (section 6.1), so replay issues no live query to any other participant.
* Order is spend order (section 7.2), which is fixed by the network, not by the observer.

One edge case is stated rather than assumed away. A verifier replaying at a later time uses the headers it holds at that time. If a header a proof anchored to was later reorganised away, the replay result MAY differ from the original. That is the correct outcome, and it is handled by the reorganisation path below, not by pinning stale headers.

#### 7.4 Reorganisation [#74-reorganisation]

A reorganisation invalidates previously accepted actions in the affected window. There is no real-time retraction channel, and this specification does not invent one. Detection is by observation on the next retrieval cycle: a response either omits an entry the reader had recorded as the chain successor, or returns one whose ancestry does not match the reader's own log. The chain-integrity check of section 6.2 is what flags the divergence.

On detection, a reader MUST:

1. roll back to the most recent state anchor whose chain still matches the post-reorganisation chain;
2. reset its position to that anchor;
3. resume walking forward from there, redispatching the new chain in canonical order;
4. mark every dispatch during that window as a resynchronisation so that application code can distinguish replay from live traffic.

If no anchor exists at that exact point, a reader falls back to the nearest earlier anchor and replays forward, at a cost proportional to the window.

#### 7.5 Dead-lettering [#75-dead-lettering]

Any failed step routes the action to a local dead-letter record, never to the application. A dead-letter carries the raw transaction, the time of receipt, a reason drawn from a fixed set (including `integrity-fail`, `decode-fail`, `key-missing`, `cross-ref-invalid` and `chain-break-timeout`) and optional detail. Dead-letters are an operator surface. They are rarely reprocessed automatically, because most of them are symptoms of a defect or an attack rather than of transient conditions.

### 8. Size budget [#8-size-budget]

The network permits very large data pushes. This specification sets a lower reference expectation of **100 kB per data field**, because individual nodes enforce their own policy caps well below the consensus limit and 100 kB is accepted broadly without special configuration. Operators targeting more permissive infrastructure MAY raise it; this specification does not document above it.

The budget is comfortable in practice because large values do not travel inline. A record whose fields are all inline runs to a few kilobytes. A record carrying a multi-megabyte value by reference costs a few hundred bytes for that field, since only the integrity manifest and the encrypted key material stay inline. A realistic record with several small inline fields and one multi-megabyte external field lands around 4 kB.

Where a record would exceed the cap, the required response is, in order:

1. move large fields to external or side-channel placement, which is the design tool for exactly this;
2. failing that, fail the write with a stated size error.

Splitting across fields or entries is the reserved escape path of section 2.2 and is not available in this version.

### 9. What the audit layer does not protect against [#9-what-the-audit-layer-does-not-protect-against]

Stated plainly, so that nothing here is read as a stronger guarantee than it is.

**Correlation is not closed by per-record keys alone.** Keys no longer cluster a chain, but three channels remain. An observer who can watch a topic sees that a set of records belongs to that topic. Anyone holding a participant's root can re-derive every commitment key and correlate everything, which is by design and is how a participant audits itself. And a chain can still be approached heuristically through funding sources, change, timing and amounts, which is materially weaker than key reuse but not nothing.

**Admission is not integrity.** A node admitting a record asserts that it parsed, not that it is correct. Sections 6.1 and 6.2 are the guarantees, and they run at the reader.

**Chain integrity is not observable to non-recipients.** Section 6.2 states the limit; it is repeated here because it is the most common misreading of the model.

**Origin markers are not unique by protocol.** Section 4.1 states why this is safe and what a consumer must do instead.

***

## Addressing, admission and retrieval [#addressing-admission-and-retrieval]

Records reach readers through two node-side surfaces. An **admission service** decides which entries of a submitted transaction enter a named topic. A **per-topic index** answers queries against what that topic has admitted. Both are ordinary infrastructure. Neither is a trust anchor, and this specification is deliberate about keeping them that way: correctness belongs to the participant and its readers, and a node that could decide correctness would be a node whose compromise decides correctness.

### 10. Topics [#10-topics]

#### 10.1 Naming [#101-naming]

A topic name has the form `tm_<scope>`, where `<scope>` is one of:

| Scope pattern        | Purpose                                                                             |
| -------------------- | ----------------------------------------------------------------------------------- |
| `<chain-id>`         | One participant's chain. The default topic for a participant.                       |
| `<group>_<scope>`    | A shared topic carrying records from several participants that belong to one group. |
| `<chain-id>_handoff` | An inbox topic carrying entries other participants have addressed to the named one. |

Names are lowercase ASCII, underscore-separated. Both `<chain-id>` and `<group>` are opaque lowercase strings fixed when the chain or the group is created.

Topic names are globally scoped per node. Operators MUST use identifiers unique enough to avoid collision with other deployments sharing infrastructure; opaque random chain identifiers make collision negligible.

#### 10.2 Topics are not tied to participants [#102-topics-are-not-tied-to-participants]

A topic MAY serve several participants, and a participant MAY submit to several topics. Both directions are intended.

A single transaction MAY be submitted to several topics in one call. Admission is independent per topic: the same transaction MAY be admitted by some and declined by others in the same submission, and a submitter records status per topic rather than one aggregate verdict.

Where a topic carries several participants' records, a reader filters by chain identifier after decoding and reconstructs each chain's order through the spend linkage of section 7.1. Topic naming follows business scope, not participant identity.

#### 10.3 Topics are created by operators [#103-topics-are-created-by-operators]

There is no on-chain topic-creation event. A topic exists when its admission service is registered with a node, and it begins admitting immediately. An operator MUST stand up the admission service and its index BEFORE any submitter includes that topic in a submission. Retiring a topic is likewise an operator action, and outstanding submissions naming a retired topic will simply fail to admit on it; there is no redirect mechanism in this version, so operators SHOULD coordinate before retiring a topic that others are still addressing.

### 11. Admission [#11-admission]

#### 11.1 Three checks, in order [#111-three-checks-in-order]

An admission service performs exactly three checks, in this order: format, then authentication, then operator business rules.

**Format** is key-free and position-agnostic. The service scans every output of the submitted transaction and admits each one that is a conforming container carrying a well-formed record envelope. Concretely, an output is admissible when all of the following hold:

* it decodes as the container of section 2 with the data placed before the spending condition;
* it carries exactly one data field;
* that field decodes under the canonical binary encoding;
* the decoded value's top-level protocol tag equals the fixed value for this specification;
* its public-slot array is present and is an array;
* its outer encrypted structure has the general-serialisation shape, with ciphertext, initialisation vector and authentication tag all present.

An output failing any of these is silently ignored. It is not admitted, and it is not individually error-reported.

**This gate is exactly the set the reader will attempt to decode, and that is a design constraint rather than a coincidence.** The protocol tag is a top-level field of the envelope, readable without any key. The encrypted header inside is covered by an authentication tag and is readable only after a recipient unwrap, which a node MUST NOT perform because it holds no recipient key and must not be positioned to hold one. So the key-free top-level check is the only architecturally available gate, and matching it to the reader's own pre-unwrap gate is what stops a node admitting records the reader will dead-letter, or declining records the reader would accept.

**Authentication** is covered in section 14.

**Business rules** are operator-configured predicates over what format admitted. Examples are a submitter allowlist for a regulated topic, a size cap on side-channel payloads, or a format requirement on inbox entries.

#### 11.2 Business rules narrow, never widen [#112-business-rules-narrow-never-widen]

An operator hook MUST only be able to remove outputs from the format-admissible set. It MUST NOT be able to add one.

This has two mechanical requirements, and an implementation that omits either has a hole rather than a hook:

* the hook receives a defensive copy, so that mutating its own argument cannot reach the pristine set;
* the returned set is clamped by intersecting it with the pristine set.

Out-of-range indices, duplicates, indices that were never format-admissible, and indices injected by mutating the argument are therefore all dropped, and the admitted set stays in ascending order. A non-conforming output can never reach the admitted set by way of a business rule.

#### 11.3 What admission does NOT do [#113-what-admission-does-not-do]

An admission service MUST NOT perform any of the following, and an implementation that performs them is non-conforming rather than merely thorough:

* **chain continuity.** Sequencing is a writer-constructs and reader-verifies concern. A node that enforced it would be asserting an opinion about ordering that the network already enforces, and would decline valid records under conditions it cannot distinguish from attack.
* **commitment-key derivation.** This requires the participant's root, which the node does not hold and MUST NOT be given.
* **record signature verification**, at any layer, for the same reason.
* **origin uniqueness**, per section 4.1.
* **delegation validity.**

The narrowness is the point. Nodes are transport and index. Correctness is owned by the participant and its readers, and this specification does not offer a mode in which that changes.

#### 11.4 Response and idempotency [#114-response-and-idempotency]

On success, the service returns the admitted outputs per topic. Admitted outputs enter the topic's set, and every registered index for that topic receives an admission event and updates asynchronously. Consumers of index queries therefore see eventual consistency bounded by that propagation, typically tens of milliseconds.

Admission MUST be idempotent. Resubmitting the same transaction to the same topic yields the same outcome, and an already-admitted transaction is treated as success. Without this, any rebroadcast would risk a duplicate admission, and rebroadcast is a normal part of the write path.

#### 11.5 Retention of predecessor entries [#115-retention-of-predecessor-entries]

**An admission service for a chain topic MUST name every previously admitted entry that the incoming transaction consumes as retained for the historical record.**

A chain IS a historical record. Each action consumes its predecessor's entry, so the predecessors ARE the history. This is not an admission decision and interacts with nothing in section 11.1: which outputs are admitted is unchanged, and retention concerns only which already-admitted entries survive.

**A service MUST retain on every path that reaches a return, including the path where the submission fails to parse and nothing is admitted.** Otherwise a malformed submission destroys history that a well-formed one would have preserved.

The consequence of not retaining is total rather than partial, which is why this is a MUST:

* the node treats a consumed entry that is not named as stale and deletes its admitted record, and with it the stored transaction carrying that entry's proof once nothing else references it;
* index answers are re-resolved through that same storage, and entries it can no longer find are dropped from the answer silently;
* an index cannot compensate. The answer it returns names entries, not bytes, so it cannot supply a transaction the node has deleted.

The observable result is a node that serves only the chain tip. A cold-start backfill returns one action, and a reader whose cursor names an action that has since been consumed never advances again.

**Retention is necessary but not sufficient.** Storage queries scoped to the current unspent set filter out consumed entries, so an index paging over such a query still answers with the tip alone. Serving history additionally requires the index of section 12 to page over its own admission record. An operator deploying a conforming admission service without such an index pays the storage cost of retention and gets none of the benefit.

#### 11.6 Accounting for side-channel bytes, and one open item [#116-accounting-for-side-channel-bytes-and-one-open-item]

Where a submission carries field bytes on the node-side channel rather than inline, the service accounts for them against the integrity commitments it can read WITHOUT A KEY. A node cannot check them all, and this specification states exactly which subset it can, so that an implementation is not read as non-conforming for declining the impossible.

Two facts force a subset. The channel carries all entries as one unframed run, so the only thing marking where one entry ends is that field's declared size. And those declarations are not uniformly visible: a public field's manifest sits outside the outer wrap, while an audit or private field's manifest sits inside it. A node holding no recipient key can therefore neither read the sizes that frame the run nor the digests to compare against, for any record carrying a non-public side-channel field.

Readability is necessary but NOT sufficient. Even a readable manifest is unusable unless the node knows WHICH stretch of the run it describes. The run is per submission while manifests are per record, and a submission may admit several records; no ordering across records is defined, and none can be inferred. Attribution therefore exists only when exactly one output is admitted.

The resulting obligations, separated by what each actually requires:

| Condition                                             | Admitted outputs | Obligation                                                                                                                                                                |
| ----------------------------------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Sum of readable declared sizes EXCEEDS the run length | any number       | The record's own public commitments overrun the payload, which is a self-contradiction detectable without attributing anything. The node MUST decline.                    |
| Sum EQUALS the run length                             | exactly one      | Attribution is unambiguous. Slice the run in declared order and verify each slice's digest and length. Any mismatch MUST decline. This verifies the VISIBLE entries only. |
| Sum is BELOW the run length                           | exactly one      | Non-public bytes are present and their commitments are unreadable. The node MUST retain the run unverified.                                                               |
| Sum does not exceed the run length                    | two or more      | The run cannot be attributed, so no manifest can be checked against any stretch of it. The node MUST retain unverified and MUST NOT decline on this ground.               |

The total-length comparison is arithmetic over publicly visible integers. It needs neither a key nor an attribution, so no admitted-output count relieves a node of it. Per-entry digest verification needs both.

Two things this section does NOT promise, written out because both were inferred once already:

* An admitted output is NOT a statement that its side-channel bytes are correct. In every case but the second row the node stores bytes it has not checked. A consumer treating admission as an integrity guarantee is relying on something this specification does not provide.
* A passing equality is NOT a statement that the record carried no hidden field. A declared size may legitimately be zero, so a hidden zero-length field sits inside an exactly accounted run undetectably. The arithmetic bounds hidden BYTES at zero; it cannot bound hidden ENTRIES at zero. An implementation MUST NOT report the result in a form a caller could read as "nothing else was in there"; naming what was actually hashed, such as a count of the public entries verified, is the intended shape.

The end-to-end guarantee lives at the reader, which verifies every value's digest and length after decryption regardless. This section aligns the admission-tier obligation with what that tier can actually observe, rather than asserting a check no keyless implementation can perform.

**Known open item: a refusal is not currently distinguishable to the submitter.**

An admission service that declines a submission on integrity grounds does so by raising out of its admission function, which is the only refusal shape that keeps the transaction off the network at all. The alternative of returning an empty admitted set is worse and was measured: the node's own acceptance test is satisfied by a refusal that still names retained entries, so the refused transaction is broadcast and confirmed while the refusing node deliberately stores nothing, leaving the field permanently unreadable to every reader. That path was also inconsistent by chain position, since an origin action has no predecessors to retain and so was correctly suppressed, while every later action on the identical failure was not.

The cost of raising is that the refusal does not reach the submitter as a refusal. It is caught before any submitter-facing code runs, and the failed topic is projected into the response as an empty admitted list. &#x2A;*So a submitter whose transaction a node declines on integrity grounds receives a SUCCESS: no error, no reason, and nothing distinguishing it from an ordinary submission that happened to admit nothing.** Anyone debugging such a submission will look for a rejection that was never sent.

This specification states the requirement rather than blessing the behaviour:

* **A refusal SHOULD be distinguishable to the submitter.** No conforming mechanism for that exists in this version, so this is a known open item rather than a satisfied requirement.
* Until it is closed, a node MUST surface the refusal reason through an operator-visible diagnostic channel. This is the only channel at all for the retained-unverified outcome, which raises nothing and therefore produces no error line to fall back on.
* The off-network property is CONDITIONAL and MUST NOT be documented as more. Acceptance is a disjunction across topics, so a submission naming a declining topic alongside an accepting one is still broadcast. Implementations MUST state the minimum node version their refusal depends on, because a node that broadcasts unconditionally satisfies the refusal rule while losing the property the rule exists to deliver.

Resolving this properly means deciding the response contract for every class of admission failure, not only the integrity case, which is a node-wide question. Until then, an implementation conforming to this section is conforming, and the general response contract MUST be read as not yet describing this path.

### 12. The per-topic index [#12-the-per-topic-index]

#### 12.1 Registration and naming [#121-registration-and-naming]

**A node MUST register an index for each topic it hosts.** A node hosting an admission topic is NOT serving that topic until its index is registered: it will admit normally and answer nothing, so a reader's cold-start backfill and live tail both return empty against a topic that is healthy.

The index name mirrors its topic. Where the topic is `tm_<scope>`, the index is `ls_<scope>`, with the same scope string. These two prefixes are wire constants: the topic name travels in the submission's topic header and the index name travels in the query body, so two implementations that disagree about them do not interoperate.

The index answers the canonical query of section 12.2 and defines NO semantics beyond it. It is a deployment obligation, not an extension point. A reader talking to any conforming node therefore behaves identically, and takes the index name as configuration rather than deriving behaviour from it.

Operators MAY additionally deploy specialised indexes offering server-side filters. Those are optional; this one is the baseline without which the topic is unreadable.

#### 12.2 The query [#122-the-query]

```json
{
  "topic": "tm_<scope>",
  "since": { "txid": "<hex>", "outputIndex": 0 },
  "limit": 1000
}
```

* `topic` is required and MUST be non-empty.
* `since` is required and nullable. `null` requests a cold-start walk from the topic's earliest admission. A non-null value requests admissions STRICTLY AFTER that entry in canonical order; the caller advances it to the last entry received between calls.
* `limit` is optional.

Two behaviours are load-bearing and any implementation MUST match them.

**Results are in admission order**, which for a single-participant topic is that participant's chain order.

**Consumed entries REMAIN in the results.** This is not a filtering choice available to the index. It depends on the admission service having retained those entries per section 11.5; an index registered against a service that does not retain cannot serve the chain no matter how it is written, because the transactions have been deleted.

A conforming index keeps its own append-only admission record and answers the cursor from it. That is for cursor STABILITY, not for retention: a node's own pagination key is typically a millisecond timestamp, which ties between same-millisecond admissions, and a cursor that can tie is a cursor that can skip or repeat an action. Retention is what naming entries buys; the private record is what makes the ordering strict.

#### 12.3 Paging [#123-paging]

An index MAY return fewer rows than requested. It MUST NOT return more, and it MUST NOT truncate an individual row's payload.

* With NO `limit`, the page is bounded by an implementation ceiling. A reference bound is 1000 rows. This ceiling exists because sizing a page requires measuring every candidate row it could still return, and an unbounded walk re-measures nearly the whole remaining suffix on every page.
* With an EXPLICIT `limit`, the value is honoured verbatim and MUST NOT be clamped. A published parameter that quietly returns fewer rows than asked for silently narrows the caller's request; the cost of a large limit is real, and the caller owns the consequence of the limit it chose.
* A page is additionally bounded by BYTES, because a row carrying a retained side-channel run can outweigh a thousand empty admissions. A reference budget is 64 MiB.
* **The byte budget is applied by dropping whole rows, NEVER by dropping a row's retained payload.** Absence of a retained payload is the erasure signal (section 12.5), so returning a row without its bytes would tell the caller those bytes were erased while they sit on disk, forging the one signal this surface exists to make trustworthy. Fewer complete rows is safe, because the caller resumes from the cursor; less data per row is not.
* **A page MUST carry at least one row whenever any row remains**, even when that single row exceeds the byte budget on its own. This is the convergence rule, and it is not a rounding convenience: an empty page at a cursor position is indistinguishable from "you are caught up", so an oversized row would stop the reader, never be delivered, and wedge the sync there permanently. An oversized single response is a large response; a wedged cursor is a participant that silently never finishes replaying.

#### 12.4 Fail-closed rules (normative) [#124-fail-closed-rules-normative]

Every one of the following MUST be refused rather than answered. A wrong answer here is silent: the caller receives a well-formed response to a question it did not ask, and cannot tell.

| Condition                                          | Why refusing is required                                                                                                                                                                                                            |
| -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The query is not an object                         | Nothing can be validated.                                                                                                                                                                                                           |
| The query carries an unrecognised key              | A key coerced away silently answers a different question. The refusal SHOULD name every key the index does answer, so a caller who mistyped a supported key is not told it is unsupported.                                          |
| `topic` is absent, not a string, or empty          | Unscoped.                                                                                                                                                                                                                           |
| `topic` names a topic this index is not bound to   | Answering would hand out records from across the boundary the operator drew when choosing the node's topics.                                                                                                                        |
| `since` is ABSENT                                  | It is required and nullable, not optional. An absent key coerced to `null` turns a malformed delta query into a full replay for a caller that asked for a delta.                                                                    |
| `since` is present but not a valid entry reference | Same silent-wrong-answer class.                                                                                                                                                                                                     |
| `limit` is present and is not a positive integer   | Same.                                                                                                                                                                                                                               |
| `since` names an entry this topic NEVER admitted   | Treating an unknown cursor as a cold start replays the whole chain to a caller that asked for a delta. Because consumed entries are retained, an unknown cursor genuinely means never admitted, and this branch means what it says. |
| The index is known to be short a row               | See below.                                                                                                                                                                                                                          |

**The index-fault rule is the strongest of these.** Where an admission notification fails to be recorded, the submission still succeeded, because it did: the transaction WAS admitted, while the index quietly fell a row behind. A later cursor query would then walk straight past the missing action and the reader would never learn it existed, which is silent data loss rather than an error. An implementation MUST therefore latch that fault and refuse every later answer for that topic. The fault MUST be persisted, not merely held in memory, because the gap is permanent: the node records the transaction as applied regardless, so that admission can never be re-notified.

A node that answers "no such record" for a record it holds is worse than one that says it cannot answer. The first corrupts a reader's state silently; the second stops it with something an operator can act on.

Where a notification records more than one row, those writes MUST be atomic. A torn write leaves a complete-looking admission whose payload is silently absent, and absence is the erasure signal, so a torn write reads to every caller as "these bytes were erased" rather than as a fault. Atomicity converts an undetectable wrong answer into a loud refusal. It does not recover the admission, and an implementation MUST NOT claim otherwise.

#### 12.5 Point lookups [#125-point-lookups]

An index additionally answers a query addressed by entry rather than by cursor, so that a caller already holding an entry reference can fetch that one admission without walking to find it. This is what a participant needs to re-read a side-channel field it no longer holds locally, at any point in its life rather than only while tailing.

```json
{ "topic": "tm_<scope>", "outpoint": { "txid": "<hex>", "outputIndex": 0 } }
```

* `outpoint` MUST NOT be combined with `since` or `limit`. A caller sending both has not decided what it is asking, and a query carrying both MUST be refused rather than answered on one of them.
* The answer is the one matching admission, carrying its transaction's retained side-channel run exactly as the cursor walk does.
* **An entry the topic does not hold MUST be answered with an EMPTY result rather than an error.** A node holding no bytes for an action is how an erased value reads, and it is deliberately NOT distinguishable from an entry that was never admitted: absence is the erasure signal, and no tombstone is kept.
* The topic-binding rule is unchanged: an index MUST refuse a point query naming a topic it is not bound to, and MUST NOT answer for an entry admitted to another topic.

**The asymmetry with the cursor's unknown-`since` rule is deliberate and worth stating.** There the entry is a POSITION, and its absence would silently change which records the caller receives, so it fails closed. Here the entry is the SUBJECT of the question, and its absence is the answer.

Retention is keyed by topic and transaction, so every admitted output of one transaction reports that transaction's run.

#### 12.6 What an index answer carries [#126-what-an-index-answer-carries]

An answer names entries and supplies, per entry, the encoded transaction with its merkle path plus the index of the output within it. Any retained side-channel bytes ride alongside in a per-entry context field.

Two layers should not be conflated. The WIRE answer is a list of entry references with their proofs. The CONTRACT surface an implementation projects for its own readers is richer, typically carrying the decoded transaction, the output index, the spending condition, the value, the retained proof, and an admission time. The projection is the implementation's, not the wire's.

Block-header verification is NOT carried in the proof. The consumer consults its own header source to confirm the merkle root anchors into the canonical chain. This is the same rule as section 6.1, and it is what keeps the answer verifiable independently of the node that produced it.

Where an implementation stamps an admission time, it MUST populate it on every result destined for live processing. A live record whose admission time cannot be resolved fails closed, so an implementation that replaces the default projection and omits the stamp dead-letters every honest live record. Backfill is exempt, so the gap bites live traffic only.

### 13. Discovery [#13-discovery]

A service that chooses to be discoverable publishes its address on the shared infrastructure, and implementations resolve where to send by reading those records at call time. The reference deployment is designed private: it publishes no advertisement of its own and is configured with its endpoints directly.

Three postures follow, and the split is NOT exhaustive in the way it first reads.

**Discoverable.** The service publishes an advertisement naming itself, its address and the topics it serves. A submitter resolves the advertisements for the topics it needs, groups them by host, and sends each host only the topics that host advertised. A retriever resolves the same way. No operator-side endpoint configuration is required: resolution happens at every call.

**Configured.** A service that does not advertise is reached through endpoints its operators exchange out of band. This is the required posture where the existence of the deployment is itself sensitive, because an advertisement would announce it. Configuration lists endpoints against the topics each serves, and several endpoints MAY serve the same topic for redundancy: a retriever fans out and deduplicates by entry reference, and a submitter fans out and takes the union of the per-topic outcomes.

**Neither.** A node bound to a loopback address has no discovery model at all. It publishes nothing, it is not reachable off-host, and the process that uses it is configured with its address directly. Neither branch above applies to it, and this is the DEFAULT posture: every deployment gets it unless an operator deliberately widens the bind.

Behaviour is otherwise identical across postures. The choice affects ROUTING only. The same submission and retrieval wire is used in every case.

### 14. Access control [#14-access-control]

#### 14.1 The baseline wire is unauthenticated [#141-the-baseline-wire-is-unauthenticated]

Submission and retrieval carry NO per-request authentication. This is the minimum interoperable behaviour, and an implementation that requires per-request credentials on these two surfaces does not interoperate with a conforming client.

The two conforming ways to control access are stated below. They are alternatives, not layers of one design, and a deployment picks one.

**Model A: open interface, standards layered on top.** The interface stays open, and authentication, payment or additional transport requirements MAY be layered on top of the baseline by deployment-specific facilitators. That layering is explicitly not part of the minimum interoperable behaviour, so a service adopting it MUST document which standard it requires and MUST NOT assume a stock client will speak it. Application-tier filtering, such as rate limits, size caps and value floors, sits here too and is the operator's responsibility.

**Model B: control at the network boundary.** Membership is enforced before a request reaches the application, through any combination of:

* mutual TLS, with client certificates issued by the group's own certificate authority;
* an address allowlist at the firewall or reverse proxy, suited to members operating from fixed ranges;
* a private network or peering, so the public internet cannot reach the endpoint at all;
* endpoint secrecy with transport TLS, a low-friction baseline for low-stakes groups, and NOT a substitute for one of the above where the boundary is itself sensitive.

Under model B there is no application-layer membership check on the request path. Non-members do not connect. This is the model this specification recommends where the group boundary IS the privacy boundary, because it puts the control in infrastructure that already exists and keeps the wire uniform.

A note on credentials: under model B the credentials live at the network tier, and their rotation follows ordinary certificate, key and firewall lifecycles. A compromised network credential grants an attacker reach to the endpoint and nothing more. It does not affect chain integrity, because every action is independently committed under its own per-record key.

#### 14.2 Bind address is access control [#142-bind-address-is-access-control]

Where a node relies on model B, the bind address IS the control, and widening it is the act that makes the node's unauthenticated admission surface reachable. An implementation MUST default to a loopback bind and MUST require an explicit operator configuration value for anything wider.

#### 14.3 Browser-originated requests [#143-browser-originated-requests]

The network tier is sufficient against the network. It is not sufficient against a browser, and the gap is not theoretical.

Nodes commonly answer every route with permissive cross-origin headers together with a header permitting private-network access. That pair is exactly what a browser requires before it will let a page loaded from any site issue requests to a loopback-bound service and read the responses. An operator whose node is bound to loopback and who then opens a hostile page has no network-tier control left, because the request originates inside their own computer.

A node relying on its bind address as its only access control MUST therefore refuse browser-originated requests:

* refuse when an origin is declared, UNLESS the request's own site metadata says same-origin, meaning a page the node itself served;
* refuse when site metadata is present and is neither a direct navigation nor same-origin;
* refuse when the host header does not name the loopback interface.

The third rule is load-bearing rather than defence in depth. A browser derives same-origin from the name the page was LOADED from, not the address it resolves to, so a rebinding attack produces an honest same-origin label from a hostile page. Without the host check the first two rules can be walked straight through, and a genuine same-origin request carries neither of the metadata headers at all.

**This is NOT per-request authentication, and the distinction is exact.** These headers identify no principal and confer no authority. They are set by the browser and cannot be forged or removed by page script. No conforming client sends any of them. The check discriminates on HOW a request was initiated, never on WHO sent it, so the unauthenticated wire of section 14.1 is untouched and interoperability is unaffected. Where a node is deliberately bound wider, its fronting proxy owns host handling and this obligation does not apply.

### 15. Deployment profiles [#15-deployment-profiles]

| Profile                 | Topics                                                                               | Access                                                                         | Who can observe topic names          |
| ----------------------- | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------ | ------------------------------------ |
| Single operator, local  | Own chain topic; own inbox topic                                                     | Bind address (section 14.2), plus the browser refusal of section 14.3          | Nobody off-host                      |
| Single operator, public | Own chain topic; own inbox topic                                                     | Open; application-tier filtering only                                          | Anyone reaching the endpoint         |
| Group                   | Shared topic, plus per-member chain and inbox topics                                 | Network boundary (model B)                                                     | Members only                         |
| Public directory        | Own chain topic, open to anyone reaching the endpoint                                | Open                                                                           | Everyone                             |
| Bilateral               | Only the two participants' inbox topics, registered on shared private infrastructure | Network boundary, restricted to the pair and any explicitly authorised auditor | The pair, and their authorised peers |

A participant MAY hold several profiles at once by submitting to several topics.

**The profile choice is privacy-load-bearing, and the leak surface is the topic NAME.** The container and the record envelope are private under every profile. What varies is who can see that a record landed on a topic named after a particular participant. Implementations MUST NOT hard-code a default profile; it is configured when the topic is registered. A public directory participant SHOULD NOT deploy an inbox topic at all, and where it needs to receive addressed entries it MUST stand up group or bilateral infrastructure for that inbox specifically.

### 16. Security considerations [#16-security-considerations]

A node is transport and index. A compromised node CAN:

* censor, by refusing to admit a valid submission. Mitigated by submitting to redundant endpoints and monitoring admission rate;
* lie in answers, by returning stale or partial data. Mitigated by the reader verifying every returned entry through its proof and the derivation match of section 6.2, and by cross-checking against a redundant index;
* withhold admission events from a particular index. Same mitigation.

A compromised node CANNOT:

* forge an action, because the network's own rules and the per-record commitment keys prevent it;
* substitute a record's content undetectably, for any reader holding a recipient key, per section 6.2;
* consume a participant's chain entries, because the commitment key is a self-derivation.

Two further exposures are ordinary and are named rather than left implicit. An open topic is exposed to submission spam that passes format but carries no business value, mitigated by rate limits, size caps and value floors at the operator's proxy. And admission latency, typically well under 100 ms because the checks are cheap, becomes the bottleneck for a participant approaching its per-chain throughput ceiling, since only one action per chain is in flight at a time.
