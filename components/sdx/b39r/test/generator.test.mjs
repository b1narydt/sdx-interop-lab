import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
import { generateAll, SUITES, FROZEN_RANDOM, ROOT, serialize, vectorPath } from '../generate.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
const COMPONENT = path.resolve(HERE, '..')

test('LAB_SELF_TEST_ONLY: regenerating with the frozen random values reproduces every committed suite byte for byte', async () => {
  const frozen = JSON.parse(fs.readFileSync(FROZEN_RANDOM, 'utf8'))
  const { outputs, random } = await generateAll({ frozen, allowFresh: false })
  assert.deepEqual(Object.keys(random).sort(), Object.keys(frozen).sort(), 'every frozen value is used and none is drawn fresh')
  for (const [suite] of SUITES) {
    const committed = JSON.parse(fs.readFileSync(vectorPath(path.join(ROOT, 'fixtures/sdx/v1'), suite), 'utf8'))
    const regenerated = JSON.parse(serialize(outputs[suite]))
    delete committed.generator.runtime; delete regenerated.generator.runtime
    assert.deepEqual(regenerated, committed, suite)
    assert.equal(committed.claim, 'LAB_SELF_TEST_ONLY')
  }
})

test('LAB_SELF_TEST_ONLY: fresh randomness changes only the fields each case lists as randomized', async () => {
  const { outputs } = await generateAll({ frozen: {}, allowFresh: true })
  const get = (object, dotted) => dotted.replace(/\[(\d+)\]/g, '.$1').split('.').reduce((value, part) => value?.[part], object)
  for (const [suite] of SUITES) {
    const committed = JSON.parse(fs.readFileSync(vectorPath(path.join(ROOT, 'fixtures/sdx/v1'), suite), 'utf8'))
    const fresh = JSON.parse(serialize(outputs[suite]))
    assert.equal(fresh.cases.length, committed.cases.length, suite)
    fresh.cases.forEach((c, i) => {
      const was = committed.cases[i]
      const strip = value => {
        const copy = structuredClone(value)
        for (const field of was.randomized ?? []) {
          if (field === 'input.base') continue
          const parts = field.replace(/\[(\d+)\]/g, '.$1').split('.'), last = parts.pop()
          const parent = parts.reduce((v, p) => v[p], copy)
          parent[last] = 'RANDOMIZED'
        }
        return copy
      }
      assert.deepEqual(strip(c), strip(was), `${c.id}: only randomized fields differ`)
      // A field carrying at least 8 random bytes must change. A one-byte edit copied from a
      // random byte (VC-B39R key ID and tag edits) matches by chance once in 256 runs.
      for (const field of was.randomized ?? []) {
        if (field === 'input.base' || String(get(was, field)).length < 16) continue
        assert.notEqual(get(c, field), get(was, field), `${c.id} ${field} is drawn fresh`)
      }
    })
  }
})

test('LAB_SELF_TEST_ONLY: the @bsv/sdk oracle shares no node:crypto code with the checkers', () => {
  const probe = hidden => `
    import crypto from 'node:crypto'
    const counts = {}
    for (const name of ['createHash', 'createHmac', 'createCipheriv', 'createDecipheriv', 'createECDH', 'randomBytes', 'pbkdf2Sync']) {
      const original = crypto[name]
      crypto[name] = (...args) => { counts[name] = (counts[name] ?? 0) + 1; return original(...args) }
    }
    const { sdk } = ${hidden ? "await import('./oracle.mjs')" : "{ sdk: await import('@bsv/sdk') }"}
    const wallet = new sdk.ProtoWallet(sdk.PrivateKey.fromHex('11'.repeat(32)))
    const other = sdk.PrivateKey.fromHex('22'.repeat(32)).toPublicKey().toString()
    const { ciphertext } = await wallet.encrypt({ protocolID: [2, 'sdx encrypt'], keyID: 'k', counterparty: other, plaintext: [1, 2, 3] })
    await wallet.decrypt({ protocolID: [2, 'sdx encrypt'], keyID: 'k', counterparty: other, ciphertext })
    await wallet.createSignature({ protocolID: [2, 'sdx sign'], keyID: 'k', counterparty: 'self', data: [1] })
    await wallet.revealSpecificKeyLinkage({ counterparty: 'self', verifier: other, protocolID: [2, 'sdx sign'], keyID: 'k' })
    sdk.EncryptedMessage.decrypt(sdk.EncryptedMessage.encrypt([1], sdk.PrivateKey.fromHex('22'.repeat(32)), sdk.PrivateKey.fromHex('11'.repeat(32)).toPublicKey()), sdk.PrivateKey.fromHex('11'.repeat(32)))
    console.log(JSON.stringify(counts))`
  const run = hidden => JSON.parse(execFileSync(process.execPath, ['--input-type=module', '-e', probe(hidden)], { cwd: COMPONENT, encoding: 'utf8' }))
  const control = run(false), oracle = run(true)
  assert.ok((control.createHmac ?? 0) > 0 && (control.createCipheriv ?? 0) > 0, `control: @bsv/sdk normally uses node:crypto (${JSON.stringify(control)})`)
  for (const name of ['createHash', 'createHmac', 'createCipheriv', 'createDecipheriv', 'createECDH', 'pbkdf2Sync']) assert.equal(oracle[name] ?? 0, 0, `oracle ${name}`)
})

test('LAB_SELF_TEST_ONLY: --check passes from the command line', () => {
  const output = execFileSync(process.execPath, ['generate.mjs', '--check'], { cwd: COMPONENT, encoding: 'utf8' })
  assert.equal(JSON.parse(output).check, 'PASS')
})
