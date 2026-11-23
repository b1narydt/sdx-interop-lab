// LAB_SELF_TEST_ONLY harness transport for the SDX laboratory driver contract: one driver process
// per session, one JSON request per line on its standard input, one JSON response per line on its
// standard output (driver-contract.md, Transport). Node.js built-ins only.
import { spawn } from 'node:child_process'

const DEFAULT_TIMEOUT_MS = 120_000

// Runs one session: spawns the driver, writes every request, closes standard input and reads the
// responses. Each response is { ok: true, value } or { ok: false, error }; a missing response, a
// line that is not JSON, a non-zero exit status, a signal or a timeout makes every response of the
// session that is not already an error an ERROR observation (the contract's ERROR).
export function runSession(sut, requests, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return new Promise(resolve => {
    const [command, ...args] = sut.argv
    let child
    try {
      child = spawn(command, args, { cwd: sut.cwd, env: { ...process.env, ...(sut.env ?? {}) }, stdio: ['pipe', 'pipe', 'pipe'] })
    } catch (error) {
      resolve(failAll(requests, `spawn failed: ${error.message}`, null))
      return
    }
    const out = []
    const err = []
    let timedOut = false
    const timer = setTimeout(() => { timedOut = true; child.kill('SIGKILL') }, timeoutMs)
    child.stdout.on('data', chunk => out.push(chunk))
    child.stderr.on('data', chunk => err.push(chunk))
    child.on('error', error => err.push(Buffer.from(`\n${error.message}`)))
    child.stdin.on('error', () => {}) // a driver may exit before reading everything; reported below
    child.on('close', (code, signal) => {
      clearTimeout(timer)
      const stderr = Buffer.concat(err).toString('utf8').slice(0, 4000)
      const lines = Buffer.concat(out).toString('utf8').split('\n').filter(line => line.trim() !== '')
      const exit = { code, signal, timedOut }
      const responses = requests.map((_, i) => {
        if (i >= lines.length) return { ok: false, error: 'missing response' }
        try { return { ok: true, value: JSON.parse(lines[i]), raw: lines[i] } } catch { return { ok: false, error: 'response is not JSON', raw: lines[i].slice(0, 400) } }
      })
      if (lines.length > requests.length) responses.extra = lines.length - requests.length
      const bad = timedOut ? 'timeout' : signal ? `signal ${signal}` : code !== 0 ? `exit status ${code}` : null
      if (bad) for (const r of responses) if (r.ok) { r.ok = false; r.error = bad; r.exitValue = r.value; delete r.value }
      resolve({ responses, exit, stderr })
    })
    for (const request of requests) child.stdin.write(`${JSON.stringify(request)}\n`)
    child.stdin.end()
  })
}

function failAll(requests, error, exit) {
  return { responses: requests.map(() => ({ ok: false, error })), exit, stderr: '' }
}

// Runs fn over items with at most `limit` in flight, keeping the order of the results.
export async function pool(items, limit, fn) {
  const results = new Array(items.length)
  let next = 0
  const worker = async () => { while (next < items.length) { const i = next++; results[i] = await fn(items[i], i) } }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker))
  return results
}
