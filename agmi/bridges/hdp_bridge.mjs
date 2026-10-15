// agmi bridge for the HDP token-by-reference store.
//
// The store is a JSON file so the attacker side (agmi, in Python) can rewrite
// entries beneath the TokenStore API, which is the position draft -03 8.2
// names. Each invocation loads the file into an InMemoryTokenStore, does one
// op, and writes it back.
//
// Ops, one JSON object per invocation on stdin:
//   {op:"probe"}                        -> {commit, node, version}
//   {op:"seed", dir, ctx, n}            -> seeds n tokens, writes the store file
//   {op:"list", dir, ctx}               -> the store entries as agmi records
//   {op:"read", dir, ctx, reference}    -> resolveToken + verifyToken

import fs from 'node:fs'
import path from 'node:path'
import process from 'node:process'

const HDP = process.env.AGMI_HDP_REPO
if (!HDP) {
  console.error(JSON.stringify({ ok: false, error: 'AGMI_HDP_REPO is not set' }))
  process.exit(1)
}

const EXPECTED_COMMIT = 'd685849'
const EXPECTED_NODE_MAJOR = 22

const lib = await import(path.join(HDP, 'dist/index.mjs'))
const {
  issueToken, extendChain, verifyToken, storeToken, resolveToken,
  InMemoryTokenStore, generateKeyPair, contentAddressedReference,
} = lib

function storePath(dir, ctx) { return path.join(dir, `store-${ctx}.json`) }
function keysPath(dir) { return path.join(dir, 'keys.json') }

function loadStore(dir, ctx) {
  const store = new InMemoryTokenStore()
  const file = storePath(dir, ctx)
  const raw = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : []
  const entries = {}
  for (const [ref, token] of raw) entries[ref] = token
  return { store, entries, ordered: raw }
}

async function putAll(store, entries) {
  for (const [ref, token] of Object.entries(entries)) {
    await store.put(ref, token)
  }
}

function saveOrdered(dir, ctx, ordered) {
  fs.writeFileSync(storePath(dir, ctx), JSON.stringify(ordered, null, 1))
}

async function keysFor(dir) {
  const file = keysPath(dir)
  if (fs.existsSync(file)) {
    const raw = JSON.parse(fs.readFileSync(file, 'utf8'))
    return {
      privateKey: Uint8Array.from(raw.privateKey),
      publicKey: Uint8Array.from(raw.publicKey),
    }
  }
  const kp = await generateKeyPair()
  fs.writeFileSync(file, JSON.stringify({
    privateKey: Array.from(kp.privateKey),
    publicKey: Array.from(kp.publicKey),
  }))
  return kp
}

async function seed(dir, ctx, n, append = false) {
  const keys = await keysFor(dir)
  const ordered = append ? loadStore(dir, ctx).ordered : []
  const seedSalt = append ? `x${ordered.length}` : "a"
  for (let i = 0; i < n; i++) {
    let token = await issueToken({
      sessionId: `agmi-${ctx}-session`,
      principal: { id: `agmi-${ctx}-principal`, id_type: 'opaque' },
      scope: {
        intent: `agmi measurement ${i}`,
        authorized_tools: ['read'],
        authorized_resources: [`agmi-${ctx}-resource-${seedSalt}-${i}`],
        data_classification: 'internal',
        network_egress: false,
        persistence: false,
        max_hops: 4,
      },
      signingKey: keys.privateKey,
      keyId: `agmi-${ctx}-key`,
    })
    token = await extendChain(token, {
      agent_id: `agmi-${ctx}-agent-${i}`,
      agent_type: 'orchestrator',
      action_summary: append ? `the limit is ${90 + i}`
        : (ctx === 'a' ? `the limit is ${50 + i}` : `the quota is ${70 + i}`),
      parent_hop: 0,
    }, keys.privateKey)
    const store = new InMemoryTokenStore()
    await storeToken(store, token)
    // storeToken writes the token under both its UUID and its content digest
    for (const ref of [token.header.token_id, contentRefOf(token)]) {
      ordered.push([ref, JSON.parse(JSON.stringify(token))])
    }
  }
  saveOrdered(dir, ctx, ordered)
  return { ok: true, count: n }
}

function contentRefOf(token) {
  return contentAddressedReference(token)
}

async function list(dir, ctx) {
  const { ordered } = loadStore(dir, ctx)
  return { ok: true, ordered }
}

// The attacker can compute a content digest; it needs no key.
async function contentref(token) {
  return { ok: true, reference: contentAddressedReference(token) }
}

async function read(dir, ctx, reference) {
  const keys = await keysFor(dir)
  const { store, entries } = loadStore(dir, ctx)
  try {
    await putAll(store, entries)
  } catch (e) {
    return { ok: false, stage: 'put', error: `${e.constructor.name}: ${e.message}` }
  }
  let token
  try {
    token = await resolveToken(store, reference)
  } catch (e) {
    return { ok: false, stage: 'resolve', error: `${e.constructor.name}: ${e.message}` }
  }
  if (token === null) return { ok: false, stage: 'resolve', error: 'resolveToken returned null' }
  const result = await verifyToken(token, { publicKey: keys.publicKey })
  return {
    ok: result.valid === true,
    stage: 'verify',
    valid: result.valid,
    failedStep: result.failedStep,
    error: result.valid ? null : `verifyToken failed at step ${result.failedStep}: ${result.error?.message ?? ''}`,
    hops: token.chain?.length ?? 0,
  }
}

const input = JSON.parse(fs.readFileSync(0, 'utf8'))
let out
try {
  if (input.op === 'probe') {
    out = { ok: true, node: process.version, major: Number(process.version.slice(1).split('.')[0]) }
  } else if (input.op === 'seed') {
    out = await seed(input.dir, input.ctx, input.n, input.append === true)
  } else if (input.op === 'list') {
    out = await list(input.dir, input.ctx)
  } else if (input.op === 'contentref') {
    out = await contentref(input.token)
  } else if (input.op === 'read') {
    out = await read(input.dir, input.ctx, input.reference)
  } else {
    out = { ok: false, error: `unknown op ${input.op}` }
  }
} catch (e) {
  out = { ok: false, error: `${e.constructor.name}: ${e.message}` }
}
process.stdout.write(JSON.stringify(out))
