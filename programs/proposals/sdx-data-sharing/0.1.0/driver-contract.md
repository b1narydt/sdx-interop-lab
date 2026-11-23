# SDX laboratory driver contract

Version **0.1.0** of the proposed SDX data-sharing program. Result class `LAB_SELF_TEST_ONLY`.

The driver contract is the neutral interface through which a TPNIL harness runs an SDX v0.1 implementation. The laboratory's harness is `scripts/run-sdx-suts.mjs`, described under [The harness](#the-harness). An implementation supplies a driver: a command that reads requests and writes responses. The harness runs one implementation's driver as writer and another's as reader, in both directions, and compares the results with the expectations of the vector suites VA-ENV, VA-SIG, VA-KEY and VA-ADM. The contract carries test inputs and observable results only. It does not prescribe an implementation's internal interfaces, and SDX's own reader, writer and recorder port contracts (BASE §6 item 10) remain unpublished.

## Transport

- The driver reads one JSON request per line on standard input and writes one JSON response per line on standard output, in order, until standard input closes. A harness may send a single request per process.
- The steps of one VA-ADM case run in one process, because the admission service and index keep state across steps. Every other operation is stateless.
- A driver that does not support an operation answers `{"unsupported": "<op>"}`. The affected case is BLOCKED.
- A response that is not valid JSON, a missing response, or a non-zero exit status is ERROR for the case. A refusal is an ordinary response, never an error.

## Values

- Byte strings are lowercase hexadecimal, except in record values.
- Record values use one JSON model: text, safe integers, booleans and `null` as JSON; a byte string as `{"$bytes": "<hex>"}`; arrays and maps as JSON arrays and objects with text keys. An object whose only member is `$bytes` is a byte string. Values outside this model are not exchanged.
- `profile` is the repository path of the deployment profile, `fixtures/sdx/v1/deployment-profile.json` (`tpnil-sdx-lab:v1`). Every derived byte is computed under it (KEYS §1.3.1, ENV §2.1).
- Roots are 64-byte root keying material (`rootIkm`) or 33-byte compressed P-256 root public keys (`R`, recipient roots).
- Entry references are `{"txid": "<display-order hex>", "outputIndex": <n>}`.

## Records: `write` and `read`

### `write`

```json
{"op": "write", "profile": "<path>",
 "writer": {"acct": "<accountId>", "rid": "<runtimeId>", "ep": 0, "rootIkm": "<hex 64 bytes>"},
 "record": {"aid": "<ULID>", "f": "<operation>", "mv": 1, "tm": 1794700800000,
            "fields": [{"n": "<name>", "sn": "pu|au|pr", "pl": "ch",
                        "value": <value>, "cv": true, "blind": true,
                        "filename": "<text>", "mediaType": "<text>", "meta": <value>}]},
 "auditRecipients": ["<hex P-256 root>"],
 "fieldRecipients": {"<name>": ["<hex P-256 root>"]},
 "random": {"outer": {...}, "fields": {"<name>": {...}}}}
```

- `fields` is in declared order. A field without `value` is declared but unset (ENV §7); `"value": null` is a value. `cv`, `blind`, `filename`, `mediaType` and `meta` are optional; `blind` declares a writer-blind private field (ENV §9.1). The laboratory suites place every field in-record (`pl` `ch`).
- The writer adds its self-recipient to the outer wrap always (ENV §5.2), and to each private field unless the field is writer-blind; `auditRecipients` and `fieldRecipients` list only external recipients, in order.
- `random` is optional. When present, the writer uses its values instead of drawing its own: per JWE (`outer`, and each private field by name) `cek` (32 bytes), `iv` (12 bytes), `epk` (one 32-byte ephemeral private key per identity recipient, in recipient order) and, for a convergent slot, `kwiv` (12 bytes). A writer that cannot take them ignores the member; the checks that depend on them are then not applicable.
- The response is `{"envelope": "<hex>"}`, or `{"refusal": {"class": "write-refused", "detail": "<text>"}}` when the writer refuses the input (ENV §6.1, §7.1, §9, §9.1, §13; KEYS §1.6.2).

### `read`

```json
{"op": "read", "profile": "<path>",
 "reader": {"acct": "<accountId>", "rid": "<runtimeId>", "ep": 0, "rootIkm": "<hex 64 bytes>"},
 "as": "writer|reader",
 "writer": {"acct": "<accountId>", "rid": "<runtimeId>", "R": "<hex P-256 root>"},
 "envelope": "<hex>"}
```

- `as: "writer"` reads the reader's own record: its keys are self-derivations, and it can re-derive the signing key identifier (ENV §8.5). `as: "reader"` reads as a recipient, with the writer's root `R` as counterparty (ENV §8.6). The writer's account and runtime identifiers are inputs because they are not on the wire (KEYS §1.11.1).
- The response is a projection:

```json
{"tier": "nothing|audit", "verdict": "accepted|refused",
 "refusal": {"class": "<class>", "detail": "<text>"},
 "aid": "<text or null>",
 "hdr": {"f": "<text>", "mv": 1, "ep": 0, "tm": 1794700800000, "pks": "root|delegate", "pk": "<hex>", "dref": ["<hex>"]},
 "fields": [{"n": "<name>", "sn": "pu|au|pr", "state": "value|unset|redacted|unavailable|erased",
             "value": <value>, "filename": "<text>", "mediaType": "<text>", "meta": <value>}],
 "signature": {"kid": "<hex>", "shape": "current|superseded"}}
```

- `tier` is the record-level tier the reader reached (ENV §12). At `nothing`, `fields` holds the public slots in array order and there is no `hdr` or `signature`. At `audit`, `fields` holds one entry per descriptor in declared order (ENV §14 step 11), and per-field access shows in `state`.
- `value`, `filename`, `mediaType` and `meta` appear only with state `value`, and the last three only when the record carries them. `unavailable` and `erased` are reserved for field placement, which these suites do not author.
- `signature` names the verifying signature's key identifier and the candidate shape it verified on (ENV §8.3).
- A refused record carries `refusal`, an empty `fields` and no `hdr` or `signature`. Refusal classes: `format`, `structure`, `integrity`, `signature`, `decode`, `root-pk-mismatch` and `delegation-invalid`. ENV names integrity, signature and decode refusals; KEYS §2.7 names the last two.

### Comparison

- An accepted projection is compared in full: `tier`, `verdict`, `aid`, `hdr`, `fields` and `signature`. JSON objects compare by member name, arrays in order. A member the contract does not define is not judged, and a defined member that is `null` counts as absent.
- A refused one is compared by verdict, and by class only where the case's `classTag` is `required`. `detail` is never compared.
- A case tagged `labChoice` records the laboratory's outcome where the text leaves it open. A differing implementation is reported, as INCONCLUSIVE, and does not fail.
- For a `write` case, the harness passes the writer's envelope to the write checks published with the suite (`checkWrite` in `src/sdx/env.mjs`, `check_write` in `test/sdx_env.py`). It then reruns every `read` case marked `fromWrite` with that envelope, through the other implementation's driver. Each suite's `writeCheckQualification` samples show the checks failing where they should.
- A writer's refusal is compared by its presence.

### `secrets` (optional hook)

`{"op": "secrets", "data": "<hex>", "iterations": 200000}` returns `{"hash", "s1", "s2", "cek"}` in hex (ENV §4), or `{"refusal": {"class": "input", "detail": "<text>"}}` for fewer than 200000 iterations.

## Keys: VA-KEY

Each operation takes `profile`. A refusal is `{"refusal": {"class": "key", "detail": "<text>"}}`.

| Request | Response | KEYS |
| --- | --- | --- |
| `{"op": "split", "rootIkm"}` | `{"secp256k1Seed", "p256Seed"}` | §1.4.2, §1.4.3 |
| `{"op": "derive", "curve": "p256\|secp256k1", "rootIkm", "namespace", "keyPath", "counterparty": "self\|<hex public key>", "side": "own\|counterparty"}` | `{"identifier", "publicKey", "privateKey"}`; `privateKey` only for `own` | §1.6, §1.7, §1.8 |
| `{"op": "symmetric", "curve": "secp256k1", "rootIkm", "namespace", "keyPath", "counterparty"}` | `{"identifier", "key"}` | §1.8.2 |
| `{"op": "validate", "keyPath"}` | `{"verdict": "accepted"}` or `{"verdict": "refused", "detail"}` | §1.6.1 |
| `{"op": "offset", "curve", "hmac"}` (optional hook) | `{"scalar"}` | §1.8.2, §1.12 item 7 |
| `{"op": "profile", "profile": "<path>" \| {"inline": {...}}}` | `{"verdict": "conforming\|nonconforming", "failures": [...]}` | §1.12 item 11 |

`side: "own"` derives the deriver's own child: its private key and public key. `side: "counterparty"` derives the counterparty's child public key, as a writer does for a recipient (ENV §8.6). Refusal details are never compared. `validate` is compared by verdict.

`profile` failures name the rule that fails, as a set, in the laboratory profile's member names: `namespace-grammar:<role>` (KEYS §1.3), `namespaces-distinct`, `label:<curve>`, `labels-distinct` (KEYS §1.4.2), `keyword:<level>`, `purpose:<purpose>`, `purposes-distinct` (KEYS §1.6.1) and `credential-type` (KEYS §1.3.1 item 4). `<role>` is a member of `derivation.namespaces`, `<curve>` of `derivation.curveLabels` and `<level>` of `derivation.keyPath.keywords`.

**Contained keys.** An implementation whose keys never leave its key store, such as a wallet module, declares so before execution. Its `split` may answer `{"secp256k1Public", "p256Public"}`, the two seeds' public keys, and its `derive` with `side: "own"` may omit `privateKey`. The harness then compares the public keys of the expected seeds, and the derived public key alone: on a prime-order group a public key determines its private key in [1, n − 1].

## Admission and index: VA-ADM

One process per case. The first request is `{"op": "setup", "profile": "<path>", "topics": ["tm_<scope>"], "rules": {...}}`, answered `{"ok": true}`. It registers each topic with its index `ls_<scope>` (ANC §10, §12.1) and the case's laboratory business rules (`drop`, `inject` or `mutate` with `outputs`; ANC §11.2).

| Request | Response |
| --- | --- |
| `{"op": "submit", "topics": [...], "tx": "<raw transaction hex>", "offChain": "<hex run>"}` | `{"topics": {"<topic>": {"admitted": [<output index>], "retained": [<entry reference>], "declined": false, "sideChannel": {"accounting": "verified\|unverified", "publicEntriesVerified": <n>}}}}` |
| `{"op": "lookup", "service": "ls_<scope>", "query": {...}}` | `{"rows": [{"txid", "outputIndex", "offChain"}]}` or `{"refusal": {"class": "query", "detail"}}` |
| `{"op": "fault", "topic"}` (optional hook) | `{"ok": true}` after the index has fallen a row behind |

- `offChain` is the submission's side-channel run. `sideChannel` appears only with a run.
- A declined submission (ANC §11.6) is reported as `"declined": true` with nothing admitted or retained. A service reports it through its diagnostic channel, because ANC §11.6 leaves the submitter's view of a refusal open.
- `query` is the ANC §12.2 cursor query or the ANC §12.5 point query, as given.
- Rows are compared as entry references, in order, with the retained run. A query refusal is compared by its class.
- Transactions are raw. Their parents are in the suite file. A harness driving an engine that requires proofs wraps them for its controlled network.

## The harness

`node scripts/run-sdx-suts.mjs --sut <declaration>=<checkout> [--sut …] [--repeat 2]` runs implementations through this contract. Its library is `src/sdx/harness/` (Node.js built-ins and the laboratory's checker modules only, never generator code).

- **Declarations.** Each implementation has a declaration (`tpnil-sdx-sut-declaration@0.1.0`, defined in [`run-record.schema.json`](run-record.schema.json)), fixed before execution: the implementation, how its driver is built and started, its roles, and which optional provisions it offers. A write case that uses a provision the declaration does not offer (`cv`, ENV §4; `blind`, ENV §9.1) and expects an envelope is NOT_APPLICABLE, with the reason; a write the case expects refused runs for every writer. `random` goes only to a writer that declares it, and the write checks that depend on it are otherwise not applicable.
- **What runs.** Every case of VA-ENV, VA-SIG, VA-KEY and VA-ADM through each implementation; every `fromWrite` read rerun on each implementation's own envelope through every implementation, which makes the matrix: each ordered pair of implementations, self-pairs included, is a cell. VA-ENC and VA-ANC have no operation in this contract, so their cases are BLOCKED.
- **Outcomes.** PASS, FAIL, BLOCKED, INCONCLUSIVE, ERROR or NOT_APPLICABLE per case, each with a reason. `unsupported` is BLOCKED. A missing response, a line that is not JSON or a non-zero exit status is ERROR. A `labChoice` difference is INCONCLUSIVE. In VA-ADM, a step after a BLOCKED or ERROR step is not judged. A case whose outcome or observed projection differs between repetitions is INCONCLUSIVE.
- **Earlier revisions.** A driver built to an earlier revision of this contract lists its gaps in its declaration (`contractGaps`): projection members it lacks, its own refusal classes, and the class it answers for a request it cannot use. A difference these gaps explain is BLOCKED, never FAIL; everything else is judged as usual.
- **Run records.** Each run writes `runs/<run-id>/record.json` (`tpnil-sdx-run-record@0.1.0`, [`run-record.schema.json`](run-record.schema.json)) and `runs/<run-id>/transcript.jsonl`, every driver request and response of every repetition. The record names the contract, the deployment profile, every suite and harness file by SHA-256, each implementation's declaration and revision, and every outcome. It is `LAB_SELF_TEST_ONLY`.

## Versioning

This contract is versioned with the program. Members may be added. An existing member is never renamed or given a new meaning within a version.
