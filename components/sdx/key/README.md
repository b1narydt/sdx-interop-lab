# SDX key-derivation vector generator

`LAB_SELF_TEST_ONLY`. Generates `fixtures/sdx/v1/va-key/vectors.json` (VA-KEY, row SDX-A-08): the KEYS §1.12 known-answer tests under the laboratory deployment profile `tpnil-sdx-lab:v1`, on both curves, as requests of the laboratory driver contract (`split`, `derive`, `symmetric`, `validate`, `offset`, `profile`).

```sh
npm ci
node generate.mjs --check
node generate.mjs --write
```

| KEYS §1.12 item | Cases |
| --- | --- |
| 1 Root split | Five roots; a 32-byte root refused; a root whose P-256 seed is at least n refused (found by `components/sdx/p256/grind`) |
| 2 secp256k1 cross-check | Derivations and the symmetric key, each equal to `@bsv/sdk` 4.0.1 |
| 3 P-256 derivation | Private scalar and public key for three identifiers |
| 4 ES256 round trip | Exercised by VA-SIG on record signatures |
| 5 Counterparty symmetry | Both curves |
| 6 Curve independence | Ten roots, each with at least 100 differing seed bits |
| 7 Scalar rejection | A found P-256 identifier whose offset is at least n; injected offsets 0, 1, n − 1, n, n + 1 and 2^256 − 1 on both curves through the optional `offset` hook |
| 8 Normalisation | `a` followed by U+0301 becomes the composed form, on both curves |
| 9 Identifier assembly | The KEYS §1.8.1 worked example |
| 10 Grammar | Every registered purpose and both variants accepted; an unregistered purpose, a foreign keyword, an empty or extra segment and an over-long path refused; namespaces outside the profile refused |
| 11 Profile conformance | The laboratory profile and ten non-conforming variants |

The generator uses `@noble/curves` and `@noble/hashes` 2.4.0, and requires `@bsv/sdk` 4.0.1 to agree on every secp256k1 value. The oracles are `src/sdx/keys.mjs` (Node.js built-ins) and `test/sdx_key.py` (Python standard library). Neither imports anything from this folder.
