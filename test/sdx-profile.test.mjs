// The laboratory deployment profile (fixtures/sdx/v1/deployment-profile.json): its strings meet
// the grammar and distinctness rules of KEYS §1.3, §1.4.2, §1.6 and §1.7 and ENV §8.6, the
// result KEYS §1.12 item 11 has a deployment publish with its profile.
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'

const PROFILE = JSON.parse(fs.readFileSync(new URL('../fixtures/sdx/v1/deployment-profile.json', import.meta.url)))

// KEYS §1.3: lowercase letters, digits and spaces; 5 to 280 characters; no consecutive spaces;
// not ending with the word `protocol`.
const spaceForm = name => /^[a-z0-9 ]{5,280}$/.test(name) && !name.includes('  ') && !/(^| )protocol$/.test(name)

test('LAB_SELF_TEST_ONLY: the laboratory deployment profile is published and meets KEYS §1.12 item 11', () => {
  assert.equal(PROFILE.schema, 'tpnil-sdx-deployment-profile@0.1.0')
  assert.equal(PROFILE.claim, 'LAB_SELF_TEST_ONLY')
  assert.equal(PROFILE.profile, 'tpnil-sdx-lab:v1')
  assert.equal(PROFILE.formatIdentifier.value, 'tpnil-sdx-lab:v1')
  assert.notEqual(PROFILE.formatIdentifier.value, 'sdx:record:v1') // ENV §2: never the example value
  const { namespaces, curveLabels, keyPath, credentialType, securityLevel } = PROFILE.derivation
  assert.equal(securityLevel, 2) // KEYS §1.7
  const roles = ['encryption', 'signing', 'delegation', 'transportAuthentication', 'rotation', 'handoff']
  const names = roles.map(role => namespaces[role])
  for (const name of names) assert.ok(spaceForm(name), name)
  assert.equal(new Set(names).size, 6) // KEYS §1.7: the six namespaces are distinct
  assert.ok(/^[\x21-\x7e]+$/.test(curveLabels.secp256k1) && /^[\x21-\x7e]+$/.test(curveLabels.p256))
  assert.notEqual(curveLabels.secp256k1, curveLabels.p256) // KEYS §1.4.2
  const words = Object.values(keyPath.keywords)
  for (const word of words) assert.ok(word.length > 0 && !word.includes('/'), word)
  assert.equal(new Set([keyPath.keywords.level1, keyPath.keywords.level2, keyPath.keywords.level3]).size, 3)
  assert.equal(keyPath.keywords.level3, 'action') // reading R1: one level-3 keyword on both curves
  const purposes = keyPath.purposes.map(p => p.purpose)
  for (const purpose of purposes) assert.ok(purpose.length > 0 && !purpose.includes('/'), purpose)
  assert.equal(new Set(purposes).size, purposes.length)
  assert.ok(credentialType.value.length > 0)
  const ids = PROFILE.recordKeyIdentifiers
  assert.notDeepEqual(ids.signing.protocolID, ids.recipient.protocolID) // ENV §8.6
  assert.deepEqual(ids.signing.protocolID, [2, namespaces.signing])
  assert.deepEqual(ids.recipient.protocolID, [2, namespaces.encryption])
  assert.deepEqual(ids.commitment.protocolID, [2, namespaces.signing]) // ANC §3.1: no separate scope
  for (const id of [ids.signing.keyID, ids.recipient.keyID, ids.commitment.keyID]) assert.equal(id, `${keyPath.keywords.level1}/<accountId>/${keyPath.keywords.level2}/<runtimeId>/${keyPath.keywords.level3}/<actionId>`)
  assert.equal(PROFILE.profileConformance.result, 'PASS')
  assert.ok(PROFILE.anchoring.minimumEntryValue >= 1) // ANC §2.4
})
