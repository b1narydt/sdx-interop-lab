# SDX data-sharing interoperability and conformance

Version **0.1.0**, status **PROPOSED**, no program identifier assigned. Result class `LAB_SELF_TEST_ONLY`.

This proposal defines requirements, applicability, acceptance, vector suites and source coverage for interoperability between independent implementations of the SDX Protocol data-sharing specification. The [profile](profile.json) is the machine-readable requirement inventory. The [driver contract](driver-contract.md) is the neutral interface through which a harness runs implementations against the suites and against each other. The [coverage](coverage.json) inventory maps the requirement-bearing sections and conformance items of the pinned SDX v0.1 text to requirement rows or recorded gaps. [Laboratory runs](#laboratory-runs) records the first runs of two SDX implementations through that contract, as `LAB_SELF_TEST_ONLY` self-test evidence. The [promotion](promotion.md) record lists the maintainer decisions and repository changes that would turn the proposal into a registered program. TPNIL maintainers assign program identifiers. Until an assignment, the proposal sits outside the [program register](../../../README.md), `npm run check` does not read it, and registered programs and their results are unchanged.

## Purpose

SDX v0.1 states that two independent implementations are interoperable when they reconstruct identical state from the same ordered log, verify each other's records without trusting the other's storage, and anchor to the same public audit layer (BASE §6). This program makes those properties observable between independent implementations.

- **Phase A** evaluates the published SDX v0.1 text, unchanged.
- **Companion rows** record proposed requirements from two contributed BRC draft statements: a wallet module that holds SDX accounts and serves both of their key trees, P-256 and secp256k1, behind the standard BRC-100 interface; and a recipient protector for BRC-39 wallet data files. Neither changes SDX.

Draft statements define proposed requirements. Normative changes precede evaluations that rely on them, so companion rows bind no evaluation until matching text is adopted and pinned.

## Pinned sources

Each SDX page is retained byte for byte, below a TPNIL provenance header, under `fixtures/sdx/v1/standards/text/`. The [text index](../../../../fixtures/sdx/v1/standards/text/index.json) records each source URL, retrieval time and digest. The edition is the SDX Protocol specification v0.1, dated 2026-07-17 and revised 2026-09-01; its keys, envelope and anchoring sections were ratified on 2026-09-01. Requirement citations use these clause prefixes:

| Prefix | Pinned text | Source page |
| --- | --- | --- |
| BASE | [Base protocol specification v0.1](../../../../fixtures/sdx/v1/standards/text/base.md) | <https://sdxprotocol.org/protocols/data-sharing/v0.1/> |
| KEYS | [Keys, identity and delegation](../../../../fixtures/sdx/v1/standards/text/keys.md) | <https://sdxprotocol.org/protocols/data-sharing/v0.1/keys/> |
| ENV | [The record envelope and field placement](../../../../fixtures/sdx/v1/standards/text/envelope.md) | <https://sdxprotocol.org/protocols/data-sharing/v0.1/envelope/> |
| ANC | [Anchoring, addressing and retrieval](../../../../fixtures/sdx/v1/standards/text/anchoring.md) | <https://sdxprotocol.org/protocols/data-sharing/v0.1/anchoring/> |
| VEC | [Test vectors](../../../../fixtures/sdx/v1/standards/text/vectors.md) | <https://sdxprotocol.org/protocols/data-sharing/v0.1/vectors/> |
| LIC | [Licence](../../../../fixtures/sdx/v1/standards/text/licence.md) | <https://sdxprotocol.org/licence/> |

The envelope page numbers its two parts separately. ENV clauses refer to its first part, *The record envelope*; clauses of its second part, *Field placement*, are cited as ENV-FP.

KEYS, ENV, ANC and VEC each state that where the text and a published test vector disagree, the vector wins and the text is corrected. Published SDX vectors therefore take precedence over the pinned text for the bytes they pin, and TPNIL records any disagreement as a source finding.

Draft statements contributed by Binary Distributed Technologies Inc. are retained unchanged under `fixtures/sdx/v1/standards/draft-statements/`, with their [index](../../../../fixtures/sdx/v1/standards/draft-statements/index.json). None has been adopted by the SDX working group or by any standards body.

| Prefix | Draft statement | Proposed route |
| --- | --- | --- |
| SDXM | [BRC draft: SDX account keys on both curves as a BRC-98 module](../../../../fixtures/sdx/v1/standards/draft-statements/brc-draft-sdx-module.md) | BRC process |
| B39R | [BRC draft: a recipient protector for BRC-39 wallet data files](../../../../fixtures/sdx/v1/standards/draft-statements/brc-draft-brc39-recipient-protector.md) | BRC process |

## Roles and matrix

| Role | Evaluated behaviour |
| --- | --- |
| Writer | Builds, signs, encrypts and anchors records |
| Reader | Verifies records and decrypts the entries addressed to it |
| Verifier | Checks signatures against the keys they name, grants, chain rules and anchor proofs. It holds audit-tier access (ENV §12), obtained through an outer identity slot or the record-level key, and no field key. Header and signature checks need that access (ENV §6.1). The ANC §6.2 chain-integrity check also needs the writer's root, because the commitment key is a self-derivation (ANC §3.1), so a verifier performs it only for records whose root it holds. Authorship of a root-signed action is confirmed only by a root-holder (ENV §8.5) |
| Runtime | Dispatches actions under grants, and switches or hands over accounts |
| Admission service | Admits outputs to topics and answers the per-topic index (ANC §11, §12) |
| Wallet substrate | A BRC-100 wallet that holds an implementation's keys. Stock-wallet rows install no extension; companion P256 and K1 rows apply only to a configuration that installs the `p sdx` module |

Every interoperability row runs in both directions between at least two independent implementations: A writes and B reads or verifies, then B writes and A reads or verifies. Each ordered pair of admitted implementations is a separate matrix cell for every applicable row. Self-pairs supplement cross-implementation cells and never replace them. Wallet-substrate rows run against wallets admitted through TPNIL [intake](../../../../docs/intake.md). Reference implementations meet the same admission criteria and requirements as every other submission. A pairwise sample is exploration and cannot replace required cells; uncovered cells are declared below.

## Applicability

Applicability is fixed before execution from the implementation's intake declaration:

1. **Roles** from the table above.
2. **Capabilities:** `sdx-module` and `brc39-recipient-protector`.
3. **Deployment profile strings.** Derived bytes are profile-relative (KEYS §1.12). Every TPNIL SDX suite is computed under one published laboratory profile, [`fixtures/sdx/v1/deployment-profile.json`](../../../../fixtures/sdx/v1/deployment-profile.json) (`tpnil-sdx-lab:v1`). It holds the KEYS §1.3.1 values (namespaces, per-curve labels, key-path keywords and purposes, credential type) and the ENV §2.1 values (format identifier, protocol identifiers, key identifier grammar). Its format identifier is the laboratory's own; its other strings are the SDX example values, used in the laboratory only. An implementation that cannot run under this profile is BLOCKED on byte-exact rows unless a vector set computed under its own published profile is admitted with an independent oracle.

Phase A rows apply to every SDX v0.1 implementation in the roles they name. The profile states each row's rule as clauses. A row applies when any clause matches the declaration; otherwise its outcome is NOT_APPLICABLE with a recorded reason. A changed declaration creates a separately evaluated configuration.

## Outcomes and acceptance

Outcomes follow the [conformance model](../../../../docs/conformance-model.md): `PASS`, `FAIL`, `BLOCKED`, `INCONCLUSIVE`, `ERROR` and `NOT_APPLICABLE`. Aggregate precedence is ERROR, FAIL, INCONCLUSIVE, BLOCKED, PASS. Reports include the aggregate, every matrix cell and every individual outcome. Missing required observations and empty suites prevent PASS.

PASS requires every applicable mandatory row to execute successfully in two clean repetitions with matching declared semantic projections. Records carry random identifiers, content-encryption keys, nonces and ephemeral keys, so byte equality is asserted only where the pinned text makes bytes deterministic, such as deterministic encoding (ENV §3) and key derivation (KEYS §1.8). Signatures and encryption are compared by verification and decryption. Phase A rows form the mandatory set once a program identifier is assigned. Rows with status PROPOSED are never mandatory.

Records are exchanged through the [driver contract](driver-contract.md): implementation A writes, implementation B reads, and then the reverse. A writer's envelope is judged by the write checks published with VA-ENV and VA-SIG and by rerunning the suite's read cases on it through the other implementation; a reader's projection is compared with the expected one. Where a suite tags an expectation, only a `required` one can produce FAIL. A `labChoice` expectation records the laboratory's choice where the texts leave the outcome open; an implementation that differs is reported and does not fail. Anchoring outcomes are compared by the ANC §7.5 dead-letter class, never by the laboratory's own label. A refused record is compared by verdict, and by refusal class only where the case's `classTag` is `required`; the laboratory's `detail` label is never compared. A refusal caused by a laboratory bound (ENV §17.6) when reading an implementation's output is ERROR, never FAIL.

The authored vector suites are synthetic `LAB_SELF_TEST_ONLY` material. They qualify oracles and issue no SUT result.

## Phase A: SDX v0.1

Origin `standard` for every row.

| ID | Citation | Observable assertion | Applicability | TPNIL suite | SDX suites |
| --- | --- | --- | --- | --- | --- |
| SDX-A-01 | [ENV](../../../../fixtures/sdx/v1/standards/text/envelope.md) §3 | Independent implementations encode identical record values to identical bytes under the deterministic encoding profile, and their decoders reject tagged and indefinite-length items and input that is not well-formed CBOR. Decoder outcomes ENV §3 leaves open are laboratory choices and never fail an implementation | All | VA-ENC | `cbor-det-v1`, `historical-float64-decode` |
| SDX-A-02 | [ENV](../../../../fixtures/sdx/v1/standards/text/envelope.md) §8.2, §8.5 | An ES256 record signature produced by one implementation verifies in the other against the `kid` named in its protected header. A root-holder re-derives that `kid` from the root: the writer itself, or the other implementation after importing the writer's root. Altering any single byte of the signed content makes signature verification fail in both implementations | All | VA-SIG, VA-ENV | `docv2-envelope`, `dual-curve`, `historical-float64-decode` |
| SDX-A-03 | [ENV](../../../../fixtures/sdx/v1/standards/text/envelope.md) §8.6, §9, §12 | A P-256 recipient decrypts exactly the access tiers it was given (audit, one field, or all fields) and no other | All | VA-ENV | `docv2-envelope`, `dual-curve`, `placement` |
| SDX-A-04 | [ENV](../../../../fixtures/sdx/v1/standards/text/envelope.md) §5.2 | Every record carries the writer self-recipient on its outer wrap, and a writer holding only its root recovers its records from the settlement network | All | VA-ENV | `docv2-envelope` |
| SDX-A-05 | [KEYS](../../../../fixtures/sdx/v1/standards/text/keys.md) §2 | A runtime accepts a delegate-signed action under a pinned grant and refuses it when the action is out of scope, follows the grant's revocation, or is signed by a key other than the pinned key | Runtimes | VA-GRANT | Behavioural (BASE §6 item 9) |
| SDX-A-06 | [KEYS](../../../../fixtures/sdx/v1/standards/text/keys.md) §1.10; [ANC](../../../../fixtures/sdx/v1/standards/text/anchoring.md) §4.3 | A dual-signed `_rotation` action is verified and processed (KEYS §1.10.3). After it, a record signed for the new epoch under the previous root is refused as the account's, and a reader walking the chain follows the rotation action's output, committed under the new root (ANC §4.3). The rotation's wire form waits for a laboratory reading (coverage KEYS-1.10) | All | VA-ROT | None named |
| SDX-A-07 | [ANC](../../../../fixtures/sdx/v1/standards/text/anchoring.md) §2–§4, §6, §7 | A reader verifies a reference against its own header source (ANC §6.1), walks a participant's chain by spend links from a published origin or from its last processed entry (ANC §4.1, §7.1), and keeps the output whose commitment key matches the derivation for the action and epoch its record declares (ANC §2.3, §3.1, §6.2). It dead-letters substitution, a wrong action or epoch, a missing epoch root, an undecodable record and an action that consumes two tips, with the ANC §7.5 reason class, and reports a block range its header source does not hold as INCONCLUSIVE | All | VA-ANC | `utxo-chaining` |
| SDX-A-08 | [KEYS](../../../../fixtures/sdx/v1/standards/text/keys.md) §1.3.1, §1.4, §1.6–§1.8, §1.12 | Under the published laboratory profile, independent implementations derive byte-identical per-curve seeds, derivation identifiers and keys from the same roots: the KEYS §1.4.2 split, secp256k1 and P-256 derivation, counterparty symmetry on both curves, scalar rejection, field-name normalisation, derivation-identifier assembly, key-path grammar rejection and profile conformance (KEYS §1.12 items 1–11) | All | VA-KEY | `dual-curve` |
| SDX-A-09 | [ANC](../../../../fixtures/sdx/v1/standards/text/anchoring.md) §10–§12 | An admission service admits exactly the format-valid record outputs of a submitted transaction, without keys and wherever they sit (ANC §11.1), narrows but never widens through business rules (§11.2), admits records whose keys, signatures, chain or delegation it cannot judge (§11.3), answers a resubmission with the same outcome (§11.4), retains every admitted entry a submission consumes (§11.5) and accounts for side-channel bytes as far as the public manifests allow (§11.6). Its per-topic index `ls_<scope>` answers in admission order with consumed entries kept, honours an explicit limit, refuses every ANC §12.4 condition and answers point lookups (§12.5) | Admission services | VA-ADM (laboratory stand-in) | `overlay-binding` |

## Companion BRC draft statements

Status **PROPOSED** for every row. These rows apply only to wallets that install the `p sdx` module, or to implementations that support the BRC-39 recipient protector. They would be pinned to BRC text once the drafts complete the BRC process. The origin recorded in the profile is `standard` because an adopted row is pinned to BRC text; the PROPOSED status governs until then.

| ID | Citation | Observable assertion | Suite |
| --- | --- | --- | --- |
| P256-01 | [SDXM](../../../../fixtures/sdx/v1/standards/draft-statements/brc-draft-sdx-module.md) §Canonical derivation; §Roots and selection | From an account's 64-byte root, the module's `key` and `peer` results match SDX's `dual-curve` vectors when published, and its `open`, `key`, `peer`, `sign` and `decrypt` results match VC-P256. The logical protocol ID selects the account and `ep` its epoch; roles `actor` and `session` select the actor root and the session root the path names. For an account created inside a wallet, the root is derived from the wallet root, the account ID and the epoch exactly as the draft fixes it. A path whose HMAC output is at least the curve order fails and is not reduced. A threshold wallet's `sign` results are checked by verification, because its nonces are drawn jointly | VC-P256 |
| P256-02 | SDXM §Point validation | Every invalid P-256 point encoding is rejected before any scalar multiplication | VC-P256 |
| P256-03 | SDXM §Scheme, operations and carrier methods; §Roots and selection | Each operation on the wrong carrier method, every other BRC-100 method under `p sdx`, a malformed logical protocol ID, an unknown account or epoch, a path outside the profile's namespaces for the curve, a path under the rotation namespace, a `decrypt` path outside the encryption namespace, a `sign` path in the encryption namespace, a key path that breaks the KEYS §1.6.1 grammar, an unregistered purpose and a key path longer than 1,033 bytes are rejected | VC-P256 |
| P256-04 | SDXM §Permissions | `seekPermission: false` fails without a prompt, ordinary and module grants do not satisfy one another, a grant for one account does not cover another, creating an account or an epoch always prompts, and a request no grant covers is refused alike whether or not the wallet holds its account or epoch | VC-P256 (behavioural cases) |
| K1-01 | SDXM §Canonical derivation | From an account's root, the module's `k1key` and `k1peer` results equal BRC-42 on the account's secp256k1 seed: the value stock BRC-100 `getPublicKey` returns for protocol `[s, namespace]` and key ID `keyPath` in a wallet whose root is that seed. Both sides of a handoff or a delegation derive the same key | VC-SDX-K1 |
| K1-02 | SDXM §Canonical derivation (step 4) | `k1sign` returns a deterministic RFC 6979, low-S DER ECDSA signature over the 32 bytes of `hash` as given, by the key `k1key` or `k1peer` names, and the signature spends an ANC §2 record output whose commitment key `k1key` returned. A threshold wallet's `k1sign` results are checked by verification | VC-SDX-K1 |
| K1-03 | SDXM §Roots and selection | On secp256k1 too, the logical protocol ID selects the account and `ep` its epoch: two accounts and two epochs give different keys, an unknown account or epoch is rejected, and `ep` is rejected for roles `actor` and `session` | VC-SDX-K1 |
| K1-04 | SDXM §Point validation; §Scheme, operations and carrier methods | Every invalid secp256k1 `peer` encoding, a `hash` that is not 32 bytes, a `k1sign` path in the encryption namespace, a path under the rotation namespace, an unregistered purpose, a derivation offset of 0 or at least n (the KEYS §1.12 item 7 range computation), privileged requests, counterparties other than `self` and secp256k1 operations on `decrypt` are rejected, and grants cover one operation and one account | VC-SDX-K1 |
| K1-05 | SDXM §Permissions | `seekPermission: false` fails without a prompt, a `sign` grant does not cover `k1sign`, a grant for one account does not cover another, a request no grant covers is refused alike whether or not the wallet holds its account, and the `k1sign` prompt shows the hash, the path and the account | VC-SDX-K1 (behavioural cases) |
| B39R-01 | [B39R](../../../../fixtures/sdx/v1/standards/draft-statements/brc-draft-brc39-recipient-protector.md) §1 | A recipient-protected file opens only for its recipient, and opens to the exact plaintext | VC-B39R |
| B39R-02 | B39R §3 | A header that breaks the protector `0x02` rules is refused before unwrapping | VC-B39R |

## Vector suites

Nine suites are authored: 636 synthetic `LAB_SELF_TEST_ONLY` cases with public test keys and roots and no funded outputs. Each `vectors.json` records its requirements, citations, oracles, generator and decisions, and the [SDX fixture manifest](../../../../fixtures/sdx/v1/manifest.json) pins every suite, pinned source, checker, test, generator file and the laboratory deployment profile by SHA-256. VA-ENC, VA-ENV, VA-SIG, VA-KEY and VA-ANC have status `BASELINE-v0.1`; VA-ADM is a `LABORATORY-STAND-IN` for SDX's unpublished `overlay-binding` suite; the companion suites are PROPOSED with their rows.

| Suite | Status | Pins | Recorded oracles | Rows | Cases |
| --- | --- | --- | --- | --- | --- |
| [VA-ENC](../../../../fixtures/sdx/v1/va-enc/vectors.json) | BASELINE-v0.1 | Deterministic encoding of v0.1 records: the published SDX suites, and laboratory-derived decoder and encoder cases, each tagged `required` or `labChoice` | SDX-published `cbor-det-v1` and `historical-float64-decode` supply the expected bytes and values for cases 001 to 044; checker `src/sdx/cbor-det.mjs` (no dependencies); `test/sdx_anc.py` replays every laboratory-derived case on the Python standard library; `cborg` 6.2.1 builds the expected bytes of the encoder cases and agrees on 33 published vectors, differing on 3 where the SDX profile writes binary64 | SDX-A-01 | 75 |
| [VA-ENV](../../../../fixtures/sdx/v1/va-env/vectors.json) | BASELINE-v0.1 | SDX v0.1 record envelopes under the laboratory profile: five known-answer records written from frozen random values, with the projections the writer and three readers must reach (every tier, unset and redacted fields, the writer self-recipient, writer-blind and convergent fields); the outer protected header exactly {enc, proto, aid} and each recipient's `epk` in its own header; per-field JWEs; LZMA; the ENV §4 known answer; writer refusals; and a refusal corpus built clause by clause, each refusal tagged with its class | jose 6.2.17 opens every known-answer JWE through every recipient in the generator; `src/sdx/env.mjs` with `cbor-det.mjs`, `ec-p256.mjs` and its own LZMA decoder `lzma.mjs`, an oracle on Node.js built-ins, every case; `test/sdx_env.py`, an oracle on the Python standard library, every case | SDX-A-02, SDX-A-03, SDX-A-04 | 95 |
| [VA-SIG](../../../../fixtures/sdx/v1/va-sig/vectors.json) | BASELINE-v0.1 | ES256 record signatures on real envelopes: the detached form, the ENV §8.3 candidates with the superseded integer shape, fail-closed refusals, the signing key identifier re-derived by a root-holder, the grant-free KEYS §2.7.1 and §2.7.2 signer binding and delegate records | jose 6.2.17 verifies every known-answer signature in the generator; the same Node.js and Python oracles as VA-ENV, every case | SDX-A-02 | 32 |
| [VA-KEY](../../../../fixtures/sdx/v1/va-key/vectors.json) | BASELINE-v0.1 | KEYS §1.12 items 1–3 and 5–11 under the laboratory profile on both curves; item 4 is exercised by VA-SIG | `@bsv/sdk` 4.0.1 equals every secp256k1 derivation in the generator; `src/sdx/keys.mjs` on Node.js built-ins and `test/sdx_key.py` on the Python standard library, every case | SDX-A-08 | 69 |
| [VA-ANC](../../../../fixtures/sdx/v1/va-anc/vectors.json) | BASELINE-v0.1 | SDX v0.1 anchoring under the laboratory profile: the ANC §6.1 reference check, and the ANC §7.1 walk with the ANC §6.2 integrity check and the ANC §4.2 tip rule, outcomes named by ANC §7.5 class | Checker `src/sdx/{cbor-det,tx,anc}.mjs` on Node.js built-ins; the generator declares each outcome and the checker reproduces it; `test/sdx_anc.py` on the Python standard library, every case; `@bsv/sdk` 4.0.1 Spend, MerklePath, Beef and KeyDeriver cross-checks, including every commitment key; `cborg` 6.2.1; optional Rust participant | SDX-A-07 | 31 |
| [VA-ADM](../../../../fixtures/sdx/v1/va-adm/vectors.json) | LABORATORY-STAND-IN | Overlay admission and the per-topic index (ANC §10–§12) on real VA-ENV and VA-SIG envelopes in signed synthetic transactions: the keyless gate, business rules, records the service must admit, idempotency, retention with cold-start backfill, the §11.6 side-channel table, the §12.4 refusals and §12.5 point lookups | `@bsv/sdk` 4.0.1 validates every input and derives every commitment key in the generator; `src/sdx/adm.mjs` on Node.js built-ins and `test/sdx_adm.py` on the Python standard library, every case | SDX-A-09 | 51 |
| [VC-P256](../../../../fixtures/sdx/v1/vc-p256/vectors.json) | PROPOSED | SDX accounts in a BRC-98 module (`p sdx`), P-256 operations: the root split, roots derived inside a wallet, `open`, account and epoch selection, derivation, results and rejections | `src/sdx/p256.mjs` and `src/sdx/ec-p256.mjs` on node:crypto, every case; `test/sdx_ec.py` and `test/sdx_module.py` on the Python standard library, every value | P256-01, P256-02, P256-03, P256-04 | 177 |
| [VC-SDX-K1](../../../../fixtures/sdx/v1/vc-sdx-k1/vectors.json) | PROPOSED | SDX accounts in a BRC-98 module (`p sdx`), secp256k1 operations: `k1key`, `k1peer`, `k1sign`, account and epoch selection, and rejections | `src/sdx/k1.mjs` with `src/sdx/p256.mjs`, `src/sdx/ec-p256.mjs`, `src/sdx/brc42.mjs` and `src/sdx/tx.mjs` on node:crypto, every case; `test/sdx_ec.py` and `test/sdx_module.py` on the Python standard library, every value; the generator requires every result to equal `@bsv/sdk` 4.0.1 `ProtoWallet` `getPublicKey` and `createSignature` | K1-01, K1-02, K1-03, K1-04, K1-05 | 72 |
| [VC-B39R](../../../../fixtures/sdx/v1/vc-b39r/vectors.json) | PROPOSED | BRC-39 recipient protector (protector type 0x02) files and refusals | `src/portability/brc39-recipient.mjs` on node:crypto, independent of `src/portability/brc39.mjs`; `@bsv/sdk` 4.0.1 EncryptedMessage and BRC-100 encrypt and decrypt; `@noble/ciphers` 2.4.0 AES-256-GCM | B39R-01, B39R-02 | 37 |

The following Phase A suites are not yet authored. Their rows are planned: no case exercises them.

| Suite | Pins | Intended independent oracle | Rows |
| --- | --- | --- | --- |
| VA-GRANT | Grants, scope, revocation and pinned delegate keys | Second implementation | SDX-A-05 |
| VA-ROT | Dual-signed rotation, once the laboratory fixes a reading of the rotation format (coverage KEYS-1.10) | Second implementation | SDX-A-06 |

### SDX-published and unpublished suites

BASE §6 names seven SDX vector suites. VEC publishes two suites, which are imported unchanged under `fixtures/sdx/v1/standards/cbor-det-v1/` and keep the SDX licence ([third-party notices](../../../../THIRD_PARTY_NOTICES.md)). Both pass in full through VA-ENC.

| SDX suite | BASE §6 item | State |
| --- | --- | --- |
| `cbor-det-v1` | 1 | Published; 36 vectors |
| `historical-float64-decode` | Decode tolerance, named in the BASE §6 text outside the item table | Published; 8 vectors |
| `docv2-envelope` | 2 | Unpublished |
| `dual-curve` | 3 | Unpublished |
| `placement` | 4 | Unpublished |
| `utxo-chaining` | 5 | Unpublished |
| `overlay-binding` | 6 | Unpublished |
| `cross-domain-refs` | 7 | Unpublished |

Items 8 and 9 are behavioural. The reader, writer and recorder port contracts of item 10 are unpublished; the `/protocols/data-sharing/v0.1/interfaces` address named by BASE §6 returned HTTP 404 on retrieval.

## Uncovered cells and source coverage

- No SDX implementation has been admitted through intake, and no row has an outcome. Two pilot implementations ran through the driver contract as a laboratory self-test ([Laboratory runs](#laboratory-runs)); that run scores no row. Phase A requires at least two independent SDX v0.1 implementations admitted through intake.
- The driver contract has no operation for VA-ENC or VA-ANC, so SDX-A-01 and SDX-A-07 have run only against the laboratory's checkers, never against an implementation.
- Phase A rows SDX-A-05 and SDX-A-06 have no authored TPNIL suite. The SDX suites that would pin the bytes of SDX-A-02 to SDX-A-04 and SDX-A-08 (`docv2-envelope`, `dual-curve`) are unpublished, so the laboratory's own suites stand until they are; SDX-A-09 rests on the laboratory stand-in VA-ADM until `overlay-binding` is published.
- The suites check the laboratory's generators against its oracles. Each oracle does the JOSE steps by hand and is labelled an oracle, not an implementation; the JOSE implementation in the loop is jose 6.2.17, in the VA-ENV and VA-SIG generator.
- The [coverage](coverage.json) inventory has 94 entries for the pinned v0.1 text. It keeps a case that exists apart from a row that is only planned: 2 entries are covered and 45 partial, which means authored or SDX-published cases exercise them; 7 are planned, which means a row addresses them and no case does yet; 9 are blocked by unpublished SDX vectors or interfaces; and 31 are uncovered. Each entry lists its `cases`, and records the laboratory readings and source findings that rest on it.
- Obligations without any row include deterministic replay and drift detection (BASE §3.5, §6 item 8); discovery and access control (ANC §13, §14); field placement and externalised bytes (BASE §6 item 4; ENV §10; ENV-FP); the derivation registry (KEYS §1.9); the mandate credential, pseudonymous identity and erasure (KEYS §2.11–§2.12); write ordering and outcomes (ANC §5); replay determinism and reorganisation (ANC §7.3, §7.4); and rotation in the chain walk (ANC §4.3).

## Laboratory runs

`LAB_SELF_TEST_ONLY`. The laboratory's harness (`scripts/run-sdx-suts.mjs`, [driver contract](driver-contract.md#the-harness)) ran two SDX v0.1 implementations through the driver contract in run `2026-11-15-r1`: two repetitions, with matching outcomes and projections. The [record](runs/2026-11-15-r1/record.json) and the [transcript](runs/2026-11-15-r1/transcript.jsonl) of every driver request and response follow [`run-record.schema.json`](run-record.schema.json). The run describes these two configurations only. It is not a conformance result, it admits neither implementation, and it scores no requirement row. Neither implementation came through intake: both are pilot systems contributed with this proposal, each with a declaration fixed before execution under [`runs/declarations/`](runs/declarations/).

| Implementation | Language and JOSE implementation | Revision | Optional provisions it declares |
| --- | --- | --- | --- |
| `sdx-v01` | JavaScript; a fork of jose 6.2.13. Its keys stay in a wallet module, so it is compared under the contract's contained-keys rule | commit `9cba37c`; its folder last changed at `92aac12` | No convergent or writer-blind writes and no frozen randomness. It does not offer the `secrets` and `offset` hooks, the secp256k1 symmetric key, the per-topic index or the fault hook |
| `sdx-go` | Go; go-jose v4.1.9. Written from the pinned text alone | commit `9cba37c` | Convergent and writer-blind writes; no frozen randomness |

The two implementations share no code. Neither takes the contract's frozen random values, so the write checks that compare wrapped keys and IVs byte for byte did not apply to either; every other write check did.

Case outcomes per suite, as PASS / FAIL / INCONCLUSIVE / BLOCKED / NOT_APPLICABLE:

| Suite (cases) | `sdx-v01` | `sdx-go` |
| --- | --- | --- |
| VA-ENV (95) | 90 / 0 / 0 / 3 / 2 | 93 / 0 / 2 / 0 / 0 |
| VA-SIG (32) | 31 / 0 / 1 / 0 / 0 | 32 / 0 / 0 / 0 / 0 |
| VA-KEY (69) | 54 / 1 / 1 / 13 / 0 | 69 / 0 / 0 / 0 / 0 |
| VA-ADM (51) | 21 / 7 / 0 / 23 / 0 | 51 / 0 / 0 / 0 / 0 |
| VA-ENC (75), VA-ANC (31) | BLOCKED: no contract operation | BLOCKED: no contract operation |

The matrix reruns the 15 `fromWrite` read cases of VA-ENV and VA-SIG on each writer's own envelope through each reader. Every cell's applicable cases passed:

| Writer → reader | Cell | PASS | NOT_APPLICABLE |
| --- | --- | --- | --- |
| sdx-v01 → sdx-v01 | self-pair | 11 | 4 |
| sdx-v01 → sdx-go | cross-implementation | 11 | 4 |
| sdx-go → sdx-v01 | cross-implementation | 15 | 0 |
| sdx-go → sdx-go | self-pair | 15 | 0 |

The four not-applicable reads in `sdx-v01`'s cells read a writer-blind record and a convergent record, which `sdx-v01` does not write.

Every outcome other than PASS, with the laboratory's diagnosis against the pinned text:

- **`sdx-v01`, VA-ADM-045 to VA-ADM-051 (FAIL).** Its records topic ignores a side-channel run on an ungated topic, so it neither declines an overrun nor reports the accounting ANC §11.6 requires. Implementation.
- **`sdx-v01`, VA-KEY-050 (FAIL).** It refuses the delegation level-3 variant of KEYS §1.6.1. Its only key-path validator is its wallet module's derivation boundary, which never derives that variant (see the source finding on KEYS-1.6 in [coverage](coverage.json)). Implementation, by design.
- **INCONCLUSIVE, each a `labChoice` difference.** `sdx-v01`: VA-SIG-025, a root record with no `dref` member, which it refuses because ENV §6.1 lists the member; VA-KEY-056, a key path whose field name exceeds 256 bytes, which its derivation boundary accepts. `sdx-go`: VA-ENV-037, an envelope member outside `{proto, pu, outer}`, which it refuses; VA-ENV-095, a single recipient's `epk` in the outer protected header, which it refuses under ENV §5.2.
- **BLOCKED.** `sdx-v01` does not offer the optional `secrets` hook (VA-ENV-029 to VA-ENV-031) or `offset` hook (12 VA-KEY cases), the secp256k1 symmetric key (VA-KEY-014) or the per-topic index (`lookup` in 22 VA-ADM cases, `fault` in VA-ADM-044).
- **NOT_APPLICABLE.** `sdx-v01`'s writer-blind and convergent writes (VA-ENV-009, VA-ENV-012), which ENV §9.1 and ENV §4 leave to the writer.

Earlier runs of the same harness, which are not recorded here, found departures from the pinned text in `sdx-v01`, which were fixed, each with a test, before this run: the private plaintext's filename, media type and metadata (ENV §9, §14 step 10); an unset field that supplies them (ENV §7); field names in NFC (KEYS §1.6.2, §1.12 item 8); public slots checked before the unwrap (ENV §14 step 3); a declined field validated before it is reported redacted (ENV §9.1 rule 2); backing of a `cv` declaration (ENV §6.1 rules 5 to 9); the class of a wrong-length `dref` (KEYS §2.7.1, §2.7.2); and a corrupted LZMA stream (ENV §9). They also ran `sdx-go`'s driver built to an earlier revision of the contract, which the harness reported as BLOCKED contract gaps. The runs raised four source findings, recorded in [coverage](coverage.json) on ENV-8, ENV-9, KEYS-1.6 and KEYS-1.12.

## Recorded interpretations

Each authored suite records its decisions in the `decisions` array of its `vectors.json`, with the text each decision rests on. The lines below group them by topic and give that basis, then the suite and decision identifiers. Lines marked **Laboratory interpretation** rest on no stated rule; they remain open until SDX or the draft authors state one, or a recorded TPNIL decision fixes it. The suites also record laboratory test-construction choices, which are labelled as such. Contradictions and gaps in the pinned v0.1 text are recorded as source findings in the `sourceFindings` of the [coverage](coverage.json) entries they affect, stated against the clauses concerned, with what the laboratory does about each.

**The laboratory deployment profile**

- **Laboratory interpretation.** One level-3 keyword, `action`, names the record in every record-level key path on both curves: the ENV §8.5 signing key identifier, the ENV §8.6 recipient key identifiers, the secp256k1 audit-layer signing key and the ANC §3.1 commitment key. ENV's `<writer-scope>` is the KEYS level-2 keyword `runtime`. Basis: KEYS §1.6.1, §1.8.4, §1.11.2; ANC §3.1; ENV §8.5–§8.6 make the literals profile parameters. Source finding: KEYS writes `action` where ENV writes `record` (coverage KEYS-1.6) (deployment profile R1-ACTION-KEYWORD).
- **Laboratory interpretation.** The laboratory publishes one profile and computes every SDX suite under it. Its format identifier is `tpnil-sdx-lab:v1`, never `sdx:record:v1`; its namespace strings, per-curve labels, key-path keywords, purposes and credential type are the SDX example values, used in the laboratory only. Basis: KEYS §1.3.1, §1.12; ENV §2, §2.1 (deployment profile R2-LAB-PROFILE).

**Record envelopes**

- Write cases carry frozen random values (content-encryption keys, IVs, ephemeral keys, key-wrap IVs); given them, a writer's wrapped keys and IVs are deterministic and compared byte for byte. Ciphertexts depend on the LZMA encoder and the ES256 nonce and are judged by decryption. Each suite publishes write-check qualification samples on which the checks fail exactly where stated. Laboratory test-construction choice (VA-ENV frozen-randomness).
- **Laboratory interpretation.** The ENV §9 compression writes the .lzma "alone" container with the uncompressed size in the header and no end-of-stream marker. Writers must omit the marker (`required`); readers accept a stream with one (`labChoice`). Source findings: SDX names no container, and encoders differ at "level 9" (LZMA-JS writes a 32 MiB dictionary, liblzma 64 MiB), so compressed bytes are encoder-specific (coverage ENV-9) (VA-ENV lzma-container).
- **Laboratory interpretation.** A private plaintext is the shortest array holding every present element of [value, filename?, mediaType?, meta?], with null before the last present one; readers accept 1 to 4 elements. Source finding: the text does not fix whether trailing absent elements are written (coverage ENV-9) (VA-ENV private-tuple).
- The outer protected header holds exactly {enc, proto, aid}, plus iter and salt on a convergent record, and each identity recipient carries its own `epk`; a per-field protected header is {enc}, plus iter and salt with `cv`. Writers are held to it; readers also open a single recipient's `epk` in the protected header, which a stock JOSE library writes for one recipient (`labChoice`). Basis: ENV §5.2, §9, §11, §13 (VA-ENV outer-protected-header).
- The writer self-recipient comes first on every field it is on (`required`) and on the outer wrap (`labChoice`). Basis: ENV §5.2, §9, §13 (VA-ENV recipient-order).
- **Laboratory interpretation.** A convergent field's slot is keyed by HMAC(s2, s1) of the field plaintext and the outer convergent slot by s1 of the audit layer; the convergent slot carries no `kid`, and `salt` is base64url (`labChoice`). Source finding: ENV §9's "exactly as the record-level derivation is" against ENV §5.2 and §13 step 10, which key the outer slot with s1 (coverage ENV-4) (VA-ENV convergent-keys).
- A reader computes one candidate key per layer from the record identifier and attempts only the slot that names it; with no outer slot it stays at the Nothing tier. A field it is not a recipient of is redacted after the slot passes every check the decryption step would make; a JWE with no recipient list is refused. Basis: ENV §5.3, §8.6, §9.1 rule 2, §12, §14, §15 (VA-ENV reader-key, decline).
- The reader's checks before any unwrap are exactly the keyless ANC §11.1 admission gate: a map, the profile's `proto`, a `pu` array and an outer JWE with ciphertext, IV and tag. An envelope member outside {proto, pu, outer} is not judged (`labChoice`). Basis: ENV §2, §14 steps 1-2; ANC §11.1.
- Refusals carry a laboratory class (`format`, `structure`, `integrity`, `signature`, `decode`, `root-pk-mismatch`, `delegation-invalid`), compared only where the text names it. Laboratory test-construction choice (VA-ENV refusal-classes).
- No case exercises the ENV §15 marker-refusal rules 5, 6, 8 and 9. Source finding: they turn on each implementation's marker representation, which ENV §15 leaves open (coverage ENV-15) (VA-ENV markers-not-testable).
- Every field is placed in-record; externalised placement waits for SDX's `placement` suite. Laboratory test-construction choice (VA-ENV placement-not-authored).

**Signatures**

- The module's `sign` produces low-S ES256 signatures (s ≤ n/2); for SDX producers low-S is a SHOULD (KEYS §1.8.3); verifiers accept either S and report whether it was low-S, and a high-S signature is valid but not canonical. Basis: SDXM §Canonical derivation step 4; KEYS §1.8.3 (VC-P256 D-SIGN-LOW-S).
- `k1sign` signs the 32 bytes of `hash` as given, with an RFC 6979 nonce, in low-S form, and returns DER as BRC-100 `createSignature` does. Basis: SDXM §Canonical derivation step 4; KEYS §1.8.3 (VC-SDX-K1 D-K1-SIGN).
- The protected header is `{"alg","kid"}` in that member order with a detached empty payload. P-256 suites sign ENV §8.2 signing inputs over laboratory payloads. Basis: ENV §8.2–§8.3 (VC-P256 D-SIGNING-INPUT).
- **Laboratory interpretation.** A delegate record's signature `kid` is the hex of `hdr.pk`, the raw key pinned in the grant. Basis: KEYS §2.7.2, §2.14.1. Source finding: ENV §8.5 asks for a derived per-record key on every signature (coverage KEYS-2.7). VA-SIG exercises delegate records as far as no grant is needed; the grant checks wait for VA-GRANT (VA-SIG delegate-kid).
- **Laboratory interpretation.** An empty `dref` on a root record counts as absent. Basis: KEYS §2.7.1, which dead-letters a root action whose `dref` is present, against ENV §6.1, which lists `dref` with length 0 or 1 (coverage KEYS-2.7). A root record without `dref` is accepted (`labChoice`) and a root record with a non-empty `dref` is `delegation-invalid` (VA-SIG root-dref).
- Record signatures are ES256 over UTF-8 of protectedB64 "." base64url(signedBytes), signedBytes the deterministic encoding of {hdr, au, pr}, with `payload` "" and 64-byte P1363 values. Readers verify over the carried protected value and rebuild signedBytes from decoded values under the current shape, then once under the superseded shape, which writes integers needing the 8-byte head as binary64; any other encoding is refused. Basis: ENV §3 rule 2, §8.2, §8.3 (VA-SIG signing-input, superseded-shape).
- A root record's `kid` is the hex of the per-record signing key derived from the writer's root, and `hdr.pk` is that key. Every reader checks that a verifying signature names `hdr.pk`; only a root-holder re-derives the expected key, and a mismatch is `root-pk-mismatch`. One verifying signature suffices for a root record; a delegate record needs exactly one, naming `hdr.pk`. Basis: ENV §8.3, §8.5; KEYS §2.7.1, §2.7.2 (VA-SIG signing-kid, one-signature-suffices).
- A high-S record signature is accepted and a DER one refused, both `labChoice`. Basis: KEYS §1.8.3; ENV §16 (VA-SIG low-s).
- The rotation format is not decided. KEYS §1.10.2 makes the dual signature one concatenated value with a `dualSigned` flag, while ENV §6.1 and §8.2 use a `ds` member and a second JWS entry (coverage KEYS-1.10). VA-ROT is written only after the laboratory fixes a reading.

**Key derivation**

- **Laboratory interpretation.** A derivation whose HMAC offset is 0 or at least n fails and is never reduced. KEYS §1.8.2 both reduces the offset modulo N and requires failure at or above N; the laboratory reads the rejection as applying before reduction, as the KEYS §1.12 item 7 tests assume (coverage KEYS-1.8). VC-P256 pins a found P-256 case (VC-P256 D-OFFSET; SDXM §Canonical derivation step 3); VC-SDX-K1 injects the secp256k1 values, which no search can find, as KEYS §1.12 item 7 provides (VC-SDX-K1 D-K1-INJECT). VA-ANC's commitment-key derivation applies the same rule.
- A seed outside [1, n − 1] makes the root unusable and is never clamped; both seeds are checked before either is used. Basis: KEYS §1.4.3; SDXM §Canonical derivation step 2 (VC-P256 D-SEED).
- For an account created inside a wallet, the 64-byte root comes from the wallet root: d is the BRC-42 child private key under `[2, "admin sdx root"]`, key ID `"<accountId> <epoch>"` and counterparty `self`, and the root is HKDF-SHA-256 of d with salt `"p sdx v1"`, info `"sdx root"` and 64 bytes of output. An actor root uses key ID `actor`. The KEYS §1.4.2 split then runs unchanged. Basis: SDXM §Canonical derivation step 1; KEYS §1.4.1; BRC-42; BRC-44 (VC-P256 D-WALLET-ROOT).
- **Laboratory interpretation.** Inside key paths, `delId` and `sessionId` are lowercase hex of 16 bytes and `actorPubKey` is the lowercase hex of the compressed point; KEYS §1.6.2 gives no text form (VC-P256 D-IDS).
- On P-256 the counterparty `anyone` is the point G, as BRC-43 defines it on secp256k1. Basis: BRC-43 (VC-P256 D-ANYONE).
- VA-KEY pins the KEYS §1.12 known answers under the laboratory profile, with a found P-256 offset at least n and, through an optional hook, the injected offsets 0, 1, n − 1, n, n + 1 and 2^256 − 1 on both curves; the KEYS §1.8.1 worked example is its identifier known answer. Basis: KEYS §1.8, §1.12 (VA-KEY scalar-rejection).
- **Laboratory interpretation.** The secp256k1 symmetric key is the 32-byte x-coordinate of the derived private key times the counterparty's derived public key, as BRC-2 defines it. Source finding: KEYS §1.8.2 names only "the resulting shared material" (coverage KEYS-1.8) (VA-KEY symmetric-key).
- Account and runtime identifiers are base58 of 16 bytes and a 4-byte SHA-256d checksum, with no version byte. Source finding: KEYS §1.6.2 fixes neither (coverage KEYS-1.6). Laboratory test-construction choice (VA-ENV identifiers).

**The `p sdx` module**

- `path` is the full derivation identifier `2-<namespace>-<keyPath>`, used byte for byte, and its namespace is one the profile registers for the operation's curve; `sign` and `k1sign` reject the encryption namespace. `key` and `k1key` without `path` return the root public key, and with `peer` but no `path` they are rejected. Basis: SDXM §Scheme, operations and carrier methods and §Path scoping; KEYS §1.7 (D-PATH in the three module suites).
- `k1key` and `k1peer` equal stock BRC-100 `getPublicKey` with protocol `[s, namespace]` and key ID `keyPath` in a wallet whose root is the account's secp256k1 seed. Basis: SDXM §Canonical derivation step 3; KEYS §1.8.1; BRC-42 (VC-SDX-K1 D-K1-DERIVE).
- The protocol name is `p sdx <operation> <role> <h>`, and the logical protocol ID is exactly `<role> <h>`: one of five roles and the 32-character hex of the first 16 bytes of SHA-256 of the account ID. Basis: SDXM §Scheme, operations and carrier methods (D-LOGICAL).
- Roles `write`, `read` and `root` select the account whose tag is `<h>`, at `ep` or at the current epoch; roles `actor` and `session` select the actor root and the session root the path names, and reject `ep`. `open` returns R ‖ K, and creates an account or epoch from the wallet root only after a prompt. Basis: SDXM §Roots and selection (D-SELECT, D-OPEN).
- **Laboratory interpretation.** A `session` request whose path names no session, or that has no path, is rejected (D-SELECT).
- A grant covers one operation and logical protocol and lists derivation-identifier prefixes, which end with `/` inside a key path; requests use security level 2 and counterparty `self`, and privileged requests are rejected. Basis: SDXM §Permissions and §Path scoping (D-SCOPE).
- The actor's persistent P-256 key is `2-sdx delegate-actor/<index>` with counterparty `self`, and a key on the KEYS §2.14.1 delegation path belongs to one grant. Basis: SDXM §Canonical derivation step 1; KEYS §2.3, §2.14.1 (VC-P256 D-ACTOR).
- **Laboratory interpretation.** The `actor/<index>` key path lies outside the KEYS §1.6 account-rooted grammar, so a deployment that enforces that grammar on actor keys admits the path in its profile (VC-P256 D-ACTOR).
- Inputs are strictly deterministic CBOR maps with no unknown members, and the `decrypt` operation carries its input in the `ciphertext` of BRC-100 `decrypt`. `ep` is an unsigned integer. Basis: SDXM §Scheme, operations and carrier methods; ENV §3; RFC 7518 §4.6 (VC-P256 D-INPUT, D-DECRYPT).

**Anchoring**

- Commitment keys are the ANC §3.1 keys under the laboratory profile: BRC-42 self-derivation on the secp256k1 seed of the epoch's root, under `[2, "sdx sign"]` and key ID `account/<accountId>/runtime/<runtimeId>/action/<actionId>`. The roots are public 64-byte test values, never funded. Basis: ANC §3.1; KEYS §1.4.2, §1.8 (VA-ANC deployment-profile).
- The walk runs as the participant's own reader, which holds its root for each epoch it can read. Basis: ANC §6.2, KEYS §1.10.5. Source finding: ANC §6.2 also requires consortium recipients to perform the check, which needs the writer's root rather than a recipient key (coverage ANC-6) (root-holding-reader).
- Records are stand-ins: deterministic CBOR maps that carry `hdr.aid` and `hdr.ep` in clear, with a proto that is not the profile's format identifier, so no stand-in is a record envelope. Their decode replaces the reader's envelope decode (ENV §14), which VA-ENV will cover. Laboratory test-construction choice (stand-in-records).
- SDX v0.1 publishes no byte encoding for a reference and its proof, so VA-ANC carries one in the laboratory map `{v, aid, tx, out, beef}`, decoded strictly beyond what ENV §3 requires, until `utxo-chaining` and `cross-domain-refs` are published. Laboratory test-construction choice (reference-encoding).
- The reference check runs the five steps of ANC §6.1 in order and a recipient also runs the honest-citation guard on the action; a 64-byte transaction is never accepted as mined. A block height the header source does not hold is INCONCLUSIVE (configuration fault), and a root that differs from the held header is refused (non-canonical chain). Basis: ANC §6.1 (reference-steps, header-source, honest-citation).
- The walk starts from a published origin outpoint or the last processed entry, proves each retrieved transaction through its merkle path, requires exactly one input to consume a tip, scans every output and keeps the one whose key matches the derivation for its record. It reads no origin marker. Basis: ANC §2.3, §4.1, §4.2, §6.2, §7.1, §7.2, §12.6, §16. Source finding: ENV §6.1 defines no origin-marker member (coverage ANC-4) (walk, origin).
- The consuming input is rechecked accepting either S; the transaction is proved mined, so a recheck that does not pass is INCONCLUSIVE, never a chain verdict. Basis: KEYS §1.8.3 (spend-recheck).
- Outcomes name the ANC §7.5 dead-letter class, and an implementation must match the class, not the laboratory's label. A failure ANC §7.5 names no reason for, such as an action that consumes two tips, is the class `unlisted`. Basis: ANC §4.2, §7.5 (dead-letter-classes).
- **Laboratory interpretation.** The walk halts at the first dead-lettered action; v0.1 does not say whether a reader walks past one (walk-halts).
- **Laboratory interpretation.** When no output matches, `key-missing` and then `decode-fail` take precedence over the `integrity-fail` of ANC §7.1 step 4, because the derivation could not be attempted (no-match-reason).
- **Laboratory interpretation.** An entry of the chain that no walk from the start reaches is reported as `chain-break-timeout` once the walk ends; the verifier has no clock (unlinked-entries).
- Outpoints in the JSON fields use display byte order; transactions, BEEF and BUMPs keep internal order. Proof BEEF is BEEF V1 or Atomic BEEF, and BEEF V2 is INCONCLUSIVE. The header source is a pinned synthetic header chain and nothing is broadcast. Laboratory test-construction choice (byte-order, beef-profile, synthetic-chain).

**Admission and index**

- VA-ADM is a laboratory stand-in for the unpublished `overlay-binding` suite: steps against a fresh admission service and index, compared as admitted outputs, retained entries, the decline flag and side-channel accounting, and as entry references in order. Laboratory test-construction choice (VA-ADM stand-in).
- **Laboratory interpretation.** The admission gate compares `proto` with the profile's format identifier. Source finding: ANC §11.1 asks for "the fixed value for this specification", while ENV §2 makes it a profile parameter (coverage ANC-11) (VA-ADM gate-proto).
- The gate admits a record whose public slot every reader refuses before any unwrap. Source finding: ANC §11.1 makes the gate the reader's pre-unwrap gate, while ENV §14 step 3 refuses public-slot faults the gate does not see (coverage ANC-11) (VA-ADM gate-versus-reader).
- **Laboratory interpretation.** Retention is named on every path that returns, including a submission whose outputs fail to parse as records; a declined submission returns nothing. Basis: ANC §11.5, §11.6 (VA-ADM retention).
- **Laboratory interpretation.** Side-channel accounting counts the admitted outputs' `overlay://` public manifests only. Source finding: ANC §11.6 does not say which manifests count; only overlay bytes ride the channel (ENV-FP §2.2, §5) (VA-ADM side-channel).
- Business rules are laboratory hooks (`drop`, `inject`, `mutate`), and the index-fault rule uses an optional `fault` hook. Laboratory test-construction choice (VA-ADM rules, fault-hook).

**Encoding**

- Where ENV §3 and the published `cbor-det-v1` vectors differ, the encoder follows the vectors: out-of-domain integers and every non-integer encode as binary64, and bigint inputs are refused. Basis: VEC, which states that the vector wins (VA-ENC cbor-det-v1-profile).
- **Laboratory interpretation.** -0 encodes as integer 0, NaN as fb7ff8000000000000 and ±Infinity as binary64. The published vectors do not pin these values (VA-ENC cbor-det-v1-specials; coverage ENV-3).
- The semantic decoder rejects tags, indefinite lengths and input that is not well-formed CBOR (RFC 8949 §3, Appendix F). As laboratory choices it also rejects out-of-domain integers, maps with duplicate keys and text that is not valid UTF-8 (both well-formed but not valid, RFC 8949 §5.3.1, §5.6), and unassigned simple values. Each VA-ENC decoder case carries `basis`: `required` where ENV §3, a VEC rule or well-formedness fixes the outcome, and `labChoice` where the texts leave it open. Only `required` outcomes can fail an implementation (VA-ENC cbor-det-v1-decoder, outcomeTags).
- The strict decoder, which also requires the deterministic encoding, is a laboratory choice beyond ENV §3. Its outcomes are informative in VA-ENC and never an expectation under SDX-A-01 (VA-ENC outcomeTags).
- The checker bounds nesting depth at 64 and input at 16 MiB. ENV §17.6 requires bounds and fixes no values, so a refusal caused by one of them when reading an implementation's output is ERROR, never FAIL (VA-ENC lab-bounds).

**BRC-39 recipient protector**

- Recipient-protected files use Format Version 0x02, so a BRC-39 version-1 importer refuses them by their version. Basis: B39R §1 "Format Version"; BRC-39 §14.3 (VC-B39R D-B39R-VERSION).
- The fixed header is 35 bytes, and the additional authenticated data runs from Magic through the Wrapped Key. Import validates the header, checks the recipient, unwraps, decrypts and then checks the inner format, reporting the failing stage. Basis: B39R §1 "Header", "Export" and "Import", §3 (VC-B39R D-B39R-LAYOUT, D-B39R-AAD, D-B39R-ORDER).
- Only inner format 0x26 has vectors, because the SDX account package code is unassigned; a Wrapped Key Length that does not match the message makes unwrapping fail; the wrapped key is reachable through BRC-100 `decrypt`. Basis: B39R §1–§3 and open item 3 (VC-B39R D-B39R-INNER, D-B39R-LENGTH, D-B39R-BRC100).

**Test material**

- BRC-78 and JWE encryption draw random IVs, keys and ephemeral keys, so those values are generated once, frozen in `components/sdx/b39r/frozen-random.json` and `components/sdx/p256/frozen.json`, and checked by decryption on every run (VC-B39R D-B39R-RANDOM; VC-P256 D-DECRYPT).
- Test roots are fixed public 64-byte values and are never funded, and the wallet root of the wallet-created accounts is SHA-256 of a published label; module calls use key ID `"1"` from one laboratory originator; error codes are laboratory labels, and conformance requires the rejection, not the label (D-ROOTS, D-WALLET-ROOT, D-CALLS, D-ERRORS).
- Each module suite carries a `wallets` table, the exact wallet state its cases start from, and each module case carries the exact BRC-100 request, so an independent module can replay every executable case; [the generator's README](../../../../components/sdx/p256/README.md) gives the format (D-REPLAY).
- The VC-SDX-K1 commitment-spend case carries two synthetic version-1 transactions, nothing broadcast; `hash` is SHA-256d of the SIGHASH_ALL|FORKID preimage (VC-SDX-K1 D-K1-TX).
- The random inputs of every VA-ENV and VA-SIG record are frozen in `components/sdx/envelope/frozen.json`; VA-ADM's transactions spend a synthetic parent, carry no proof, and every input validates. Laboratory test-construction choice.

## Relationship to SDX certification

The SDX licence conveys no rights to the SDX Protocol name or marks and states that "Conformance claims are governed by the certification programme, separately" (LIC, Grant item 4). The pinned SDX texts do not describe that programme. BASE §1.3 defines conformance against the published rules and test-vector suites, never against the reference implementation, and BASE §7 states that no implementation is privileged in defining conformance.

This program can supply published, reproducible evidence that such a programme may reference: requirement rows pinned to SDX text, independent oracles, two-way runs between independent implementations, and every attempted outcome with its evidence. TPNIL issues no certification. A certification program requires separately published criteria and independent review before any certification claim is issued ([governance](../../../../GOVERNANCE.md)). Results from this program describe only the evaluated configurations and confer no right to use the SDX Protocol name or marks. The SDX working group adopts SDX requirements; TPNIL maintainers decide laboratory methods, admissions and results under the same governance.

## Profile boundaries

- The SUT is an SDX implementation with an exact artifact identity and configuration, admitted through intake: a library, runtime, reader or verifier, admission service, or a BRC-100 wallet that holds an implementation's keys. Each declared role is evaluated separately.
- Offline suites qualify oracles and component behaviour. Interoperability rows require records exchanged between two admitted implementations; an implementation's acceptance of its own output is not interoperability evidence.
- Rows that require mined anchors run on the controlled network and header source of the environment selected at promotion. SDX v0.1 leaves the naming of its settlement layer provisional (PROV-1). Public-network spending, personal wallets and production credentials are outside this profile, and spendable fixture funding requires verifiable ancestry.
- Fixtures use synthetic accounts, actors and identity-link rows. Erasure and identity rows use synthetic personal data only.
- Evaluation of any implementation, including the SDX reference implementation, follows intake and the [submission terms](../../../../legal/ARTIFACT-SUBMISSION-AGREEMENT.md). The implementation's own licence is unchanged.
- No scored evaluation relies on a PROPOSED row.

## Maintenance

Runs are reproduced with `node scripts/run-sdx-suts.mjs --sut <declaration>=<checkout> …` from the repository root; the [driver contract](driver-contract.md#the-harness) describes the harness and its outcomes. [`AGENTS.md`](AGENTS.md) takes an implementer from a first driver to a cross-implementation run, step by step. `test/sdx-harness.test.mjs` qualifies the harness with a qualification driver that answers the suites' own expectations, wrongly, not at all, or unreadably.

The [SDX fixture manifest](../../../../fixtures/sdx/v1/manifest.json) pins every SDX text snapshot, draft statement, the laboratory deployment profile, every vector suite, checker, test, generator file and proposal document by SHA-256. After a reviewed change to any of them, `node scripts/build-sdx-manifest.mjs` rebuilds the manifest from the repository root; `node scripts/build-sdx-manifest.mjs --check` reports a stale manifest without writing it. The builder uses only Node.js built-in modules and needs no npm installation. `test/sdx-manifest.test.mjs` fails on any difference and names the command. Each vector suite is regenerated by its component with `node generate.mjs --write` in `components/sdx/<component>`, and `node generate.mjs --check` confirms that the stored suite is current; the manifest is rebuilt afterwards.

## Changelog

0.1.0: initial proposal. Pinned SDX v0.1 text and frozen draft statements; a published laboratory deployment profile; 20 requirement rows (9 Phase A and 11 companion); 11 vector suites, 9 of them authored with 636 cases, including record-level envelope, signature, key-derivation and admission suites; a neutral driver contract; source coverage for the pinned text, with cases kept apart from planned rows; a fixture manifest. No program identifier assigned and no SUT admitted. A laboratory harness and run-record schema, with one `LAB_SELF_TEST_ONLY` run of two pilot implementations through the driver contract.
