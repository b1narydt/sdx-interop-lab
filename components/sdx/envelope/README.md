# SDX envelope and signature vector generator

`LAB_SELF_TEST_ONLY`. Generates `fixtures/sdx/v1/va-env/vectors.json` (VA-ENV, rows SDX-A-02 to SDX-A-04) and `fixtures/sdx/v1/va-sig/vectors.json` (VA-SIG, row SDX-A-02): SDX v0.1 record envelopes and record signatures under the laboratory deployment profile `tpnil-sdx-lab:v1`.

```sh
npm ci
node generate.mjs --check   # regenerate in memory; require identical bytes
node generate.mjs --write   # rewrite both suite files and frozen.json
```

## How a record is built

`lib/envelope.mjs` follows the ENV §13 encode flow: public, audit and private slots; per-field JWEs over the LZMA-compressed tuple (ENV §9); the header with `pk` the per-record signing key (ENV §8.5; KEYS §2.7.1); a detached ES256 signature over the deterministic encoding of {hdr, au, pr} (ENV §8.2); the outer JWE with protected header {enc, proto, aid}, plus iter and salt on a convergent record (ENV §5.2); and the envelope {proto, pu, outer} (ENV §2).

Every random value comes from the request's `random` member, which the generator fills from `frozen.json`: drawn once from node:crypto, then fixed. ES256 uses RFC 6979 low-S nonces. The output is therefore reproducible, and a writer given the same `random` values reproduces the key-management bytes the write checks compare.

Each refusal case alters one stage through a hook and leaves every other stage conforming, so the record is refused for the intended rule. The generator requires the Node oracle to refuse with the intended laboratory detail.

## Libraries and witnesses

| Library | Use |
| --- | --- |
| `@noble/curves`, `@noble/hashes`, `@noble/ciphers` 2.4.0 | P-256 key derivation, ECDH, HKDF, HMAC, PBKDF2, AES-GCM, AES key wrap, ES256 |
| `cborg` 6.2.1 | Deterministic CBOR, and the superseded integer shape of ENV §8.3 through a type encoder |
| `lzma` 2.3.2 (LZMA-JS) | LZMA at mode 9 with `disableEndMark`, the alone container with the size and no end-of-stream marker |
| `jose` 6.2.17 | A JOSE implementation (ENV §16): opens every JWE of every known-answer record through every recipient, and verifies every known-answer signature |

The generator builds JWEs on the noble primitives, because jose's GeneralEncrypt draws its own keys, and for one recipient writes `epk` into the protected header, where ENV §5.2 and §11 keep only {enc, proto, aid}. jose is the witness that the JWEs are standard.

## Oracles

`src/sdx/env.mjs` (with `cbor-det.mjs`, `ec-p256.mjs` and `lzma.mjs`) on Node.js built-ins, and `test/sdx_env.py` (with `sdx_ec.py` and `sdx_anc.py`) on the Python standard library. Both reproduce every case and every write-check qualification sample. They import nothing from this folder.

Both are oracles, not implementations: they do the JOSE steps by hand. They split the LZMA step as follows:

- The Node oracle decodes LZMA with its own decoder, which also reports whether an end-of-stream marker was written.
- The Python oracle uses the standard library's `lzma` module, which decodes either form and cannot tell them apart.
