#!/usr/bin/env node
// Generates the BRC-39 recipient-protector vector suite VC-B39R from the pinned oracles.
//
//   node generate.mjs --write          regenerate, reusing frozen-random.json, and write
//   node generate.mjs --check          regenerate in memory and require byte equality
//   node generate.mjs --fresh --out D  draw new random values and write to directory D
//
// Randomised values (BRC-78 key IDs and IVs) are drawn once, frozen in
// frozen-random.json and reused, so every other byte reproduces exactly. --fresh exists to
// show which fields depend on randomness; it never overwrites the frozen suites.
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { RandomStore } from './common.mjs'

const HERE = path.dirname(fileURLToPath(import.meta.url))
export const ROOT = path.resolve(HERE, '../../..')
export const FROZEN_RANDOM = path.join(HERE, 'frozen-random.json')
export const SUITES = Object.freeze([
  ['vc-b39r', './suites/vc-b39r.mjs']
])
export const vectorPath = (directory, suite) => path.join(directory, suite, 'vectors.json')
export const serialize = value => JSON.stringify(value, null, 2) + '\n'

export async function generateAll({ frozen = {}, allowFresh = true } = {}) {
  const random = new RandomStore(frozen, { allowFresh })
  const outputs = {}
  for (const [suite, module] of SUITES) {
    const { build } = await import(module)
    outputs[suite] = await build({ random })
  }
  return { outputs, random: random.used }
}

const withoutRuntime = text => { const value = JSON.parse(text); delete value.generator.runtime; return serialize(value) }

async function main(argv) {
  const flags = new Set(argv.filter(arg => arg.startsWith('--')))
  const outIndex = argv.indexOf('--out')
  const frozen = fs.existsSync(FROZEN_RANDOM) ? JSON.parse(fs.readFileSync(FROZEN_RANDOM, 'utf8')) : {}
  const fixtures = path.join(ROOT, 'fixtures/sdx/v1')
  if (flags.has('--check')) {
    const { outputs, random } = await generateAll({ frozen, allowFresh: false })
    const failures = []
    for (const [suite] of SUITES) {
      const file = vectorPath(fixtures, suite)
      const committed = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : ''
      const regenerated = serialize(outputs[suite])
      if (committed === regenerated) continue
      if (committed && withoutRuntime(committed) === withoutRuntime(regenerated)) {
        console.error(`${suite}: identical except generator.runtime (${JSON.parse(committed).generator.runtime} vs node ${process.versions.node})`)
        continue
      }
      failures.push(suite)
    }
    const unused = Object.keys(frozen).filter(slot => !Object.hasOwn(random, slot))
    if (unused.length) failures.push(`unused frozen slots: ${unused.join(', ')}`)
    console.log(JSON.stringify({ claim: 'LAB_SELF_TEST_ONLY', check: failures.length ? 'FAIL' : 'PASS', suites: Object.fromEntries(SUITES.map(([suite]) => [suite, outputs[suite].cases.length])), failures }, null, 2))
    if (failures.length) process.exitCode = 1
    return
  }
  if (flags.has('--fresh')) {
    if (outIndex < 0 || !argv[outIndex + 1]) throw new Error('--fresh requires --out <directory>')
    const out = path.resolve(argv[outIndex + 1])
    if (out.startsWith(path.join(ROOT, 'fixtures'))) throw new Error('--fresh never writes into fixtures/')
    const { outputs, random } = await generateAll({ frozen: {}, allowFresh: true })
    for (const [suite] of SUITES) {
      fs.mkdirSync(path.join(out, suite), { recursive: true })
      fs.writeFileSync(vectorPath(out, suite), serialize(outputs[suite]))
    }
    fs.writeFileSync(path.join(out, 'frozen-random.json'), serialize(random))
    console.log(`wrote ${SUITES.length} suites and frozen-random.json to ${out}`)
    return
  }
  if (flags.has('--write')) {
    const { outputs, random } = await generateAll({ frozen, allowFresh: true })
    for (const [suite] of SUITES) {
      fs.mkdirSync(path.join(fixtures, suite), { recursive: true })
      fs.writeFileSync(vectorPath(fixtures, suite), serialize(outputs[suite]))
    }
    fs.writeFileSync(FROZEN_RANDOM, serialize(Object.fromEntries(Object.entries(random).sort(([a], [b]) => a < b ? -1 : 1))))
    console.log(JSON.stringify(Object.fromEntries(SUITES.map(([suite]) => [suite, outputs[suite].cases.length]))))
    return
  }
  throw new Error('usage: node generate.mjs --write | --check | --fresh --out <directory>')
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch(error => { console.error(error); process.exitCode = 1 })
}
