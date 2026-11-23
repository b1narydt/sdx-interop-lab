# SDX admission and index vector generator

`LAB_SELF_TEST_ONLY`. Generates `fixtures/sdx/v1/va-adm/vectors.json` (VA-ADM, row SDX-A-09). It states overlay admission and the per-topic index (ANC §10–§12) as steps of the laboratory driver contract: `submit`, `lookup` and the optional `fault` hook, each run against a fresh admission service and index. It is a laboratory stand-in for SDX's unpublished `overlay-binding` suite.

```sh
npm ci
node generate.mjs --check   # reads the current VA-ENV and VA-SIG files
node generate.mjs --write
```

The records are real envelopes from the VA-ENV and VA-SIG files. Each is carried in an ANC §2.1 container under its ANC §3.1 commitment key, which `@bsv/sdk` derives and noble derives again. Transactions spend a synthetic parent (in the suite file) and earlier record outputs, and are signed. `@bsv/sdk` `Spend` validates every input. Nothing is broadcast, and no transaction carries a proof. A harness driving an overlay engine that requires proofs wraps them for its controlled network.

Regenerate this suite after any change to VA-ENV or VA-SIG. The suite file pins both by SHA-256.

The oracles are `src/sdx/adm.mjs` (Node.js built-ins, with `tx.mjs` and `cbor-det.mjs`) and `test/sdx_adm.py` (Python standard library, with `sdx_anc.py`). Neither imports anything from this folder.
