/**
 * Spec for the main-branch metrics job and every other job that loads Vault
 * the same way.
 *
 * actions/runner v2.338.2 sends a third-party `uses` ref to the service and
 * downloads whatever commit that ref names at execution time
 * (ActionManager.cs DownloadRepositoryActionAsync; ActionManagerL0 mocks a
 * branch ref to a fresh SHA). A 40-character commit SHA does not follow a
 * branch move. ScriptHandler and NodeScriptActionHandler copy the job's OIDC
 * request URL and request token into every script and JavaScript step when
 * the job message carries GenerateIdTokenUrl. This workflow asks for that by
 * setting `id-token: write`. get-id-token.js then exchanges those variables
 * for a JWT, and the Vault login/read in the action returns the mapped secret.
 *
 * These tests fail while a moving ref still runs with that credential or is
 * handed the secret. They pass when every third-party action that runs in
 * such a job is pinned to a full commit SHA, the stats API key is placed only
 * in the publish step's environment, and the pinned Vault action still
 * returns the mapped value to that step.
 *
 * Run:
 *   node --test .github/workflows/scripts/unpinned-vault-action.test.mjs
 */
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import fs from 'node:fs'
import http from 'node:http'
import os from 'node:os'
import path from 'node:path'
import { test } from 'node:test'
import vm from 'node:vm'
import { fileURLToPath } from 'node:url'

const here = path.dirname(fileURLToPath(import.meta.url))
const repoRoot = path.resolve(here, '../../..')
const workflowRoot = process.env.VAULT_PIN_CHECK_ROOT || repoRoot
const fixtureDir = path.join(here, 'fixtures/get-vault-secrets')
const translateScript = path.join(fixtureDir, 'translate-secrets.bash')
const tokenScript = path.join(fixtureDir, 'get-id-token.js')

const PRODUCTION = {
  event_name: 'push',
  repository: 'grafana/grafana',
  repository_owner: 'grafana',
  ref_name: 'main',
  ref: 'refs/heads/main',
}

function loadYaml(file) {
  const script = `
import json, sys, yaml
bool_values = {'true': True, 'false': False, 'True': True, 'False': False, 'TRUE': True, 'FALSE': False}
class Loader(yaml.SafeLoader):
    pass
def construct_yaml_bool(loader, node):
    value = loader.construct_scalar(node)
    if value in bool_values:
        return bool_values[value]
    return value
Loader.add_constructor('tag:yaml.org,2002:bool', construct_yaml_bool)
print(json.dumps(yaml.load(open(sys.argv[1]), Loader=Loader)))
`
  const result = spawnSync('python3', ['-c', script, file], { encoding: 'utf8' })
  if (result.status !== 0) {
    throw new Error(`failed to parse ${file}: ${result.stderr}`)
  }
  return JSON.parse(result.stdout)
}

function lookup(ctx, dotted) {
  let value = ctx
  for (const key of dotted.split('.')) {
    if (value == null || !Object.prototype.hasOwnProperty.call(value, key)) {
      return undefined
    }
    value = value[key]
  }
  return value
}

// Clauses this harness cannot parse are not treated as false: a step that
// might run is still executed. A comparison that is false skips the step.
function conditionHolds(expr, ctx) {
  if (!expr) {
    return true
  }
  for (const raw of String(expr).split('&&')) {
    const part = raw.trim()
    const equal = part.match(/^([\w.-]+)\s*==\s*'([^']*)'$/)
    if (equal) {
      // Outputs from earlier steps are not known yet. A step that can run
      // when those outputs match is still executed.
      if (equal[1].startsWith('steps.') || equal[1].startsWith('needs.')) {
        continue
      }
      const actual = lookup(ctx, equal[1])
      // A path this context does not carry is not evidence the step is skipped.
      if (actual === undefined) {
        continue
      }
      if (String(actual) !== equal[2]) {
        return false
      }
      continue
    }
    const notEqual = part.match(/^([\w.-]+)\s*!=\s*'([^']*)'$/)
    if (notEqual) {
      if (notEqual[1].startsWith('steps.') || notEqual[1].startsWith('needs.')) {
        continue
      }
      if (String(lookup(ctx, notEqual[1])) === notEqual[2]) {
        return false
      }
    }
  }
  return true
}

function parseUses(uses) {
  if (typeof uses !== 'string' || uses.startsWith('./') || uses.startsWith('docker://')) {
    return null
  }
  const at = uses.indexOf('@')
  if (at <= 0) {
    return null
  }
  return { name: uses.slice(0, at), ref: uses.slice(at + 1), raw: uses }
}

function isImmutableRef(ref) {
  return /^[0-9a-f]{40}$/.test(ref)
}

// Branch and tag refs are resolved again at execution. A previously observed
// SHA is not reused, matching the runner sending `action.Ref` to the download
// service rather than a SHA captured earlier.
function resolveActionRef(uses, tips) {
  const parsed = parseUses(uses)
  if (!parsed) {
    return null
  }
  if (isImmutableRef(parsed.ref)) {
    return { mutable: false, sha: parsed.ref, name: parsed.name }
  }
  return { mutable: true, sha: tips[parsed.ref], name: parsed.name }
}

function isVaultAction(name) {
  return name.endsWith('/get-vault-secrets')
}

function idTokenWrite(workflow, job) {
  const perms = job.permissions != null ? job.permissions : workflow.permissions
  if (perms == null) {
    return false
  }
  if (typeof perms === 'string') {
    return perms === 'write-all'
  }
  return perms['id-token'] === 'write'
}

function loadLocalAction(root, uses) {
  const rel = uses.replace(/^\.\//, '')
  for (const name of ['action.yml', 'action.yaml']) {
    const file = path.join(root, rel, name)
    if (fs.existsSync(file)) {
      return loadYaml(file)
    }
  }
  return null
}

function mergedInputs(action, callerWith) {
  const inputs = {}
  for (const [name, spec] of Object.entries(action?.inputs || {})) {
    if (spec && spec.default != null) {
      inputs[name] = String(spec.default)
    }
  }
  for (const [name, value] of Object.entries(callerWith || {})) {
    if (value != null) {
      inputs[name] = String(value)
    }
  }
  return inputs
}

function* iterateSteps(job, root, github, inheritedInputs, seen) {
  for (const step of job.steps || []) {
    const ctx = { ...github, inputs: inheritedInputs, github }
    if (!conditionHolds(step.if, ctx)) {
      continue
    }
    yield { step, inputs: inheritedInputs }
    if (typeof step.uses === 'string' && step.uses.startsWith('./')) {
      if (seen.has(step.uses)) {
        continue
      }
      seen.add(step.uses)
      const action = loadLocalAction(root, step.uses)
      if (!action?.runs?.steps) {
        continue
      }
      const inputs = mergedInputs(action, step.with)
      yield* iterateSteps({ steps: action.runs.steps }, root, github, inputs, seen)
    }
  }
}

function workflowFiles(root) {
  const dir = path.join(root, '.github/workflows')
  return fs
    .readdirSync(dir)
    .filter((name) => name.endsWith('.yml') || name.endsWith('.yaml'))
    .map((name) => path.join(dir, name))
}

function stepsWithApiKeyEnv(job) {
  const hits = []
  if (job.env && Object.prototype.hasOwnProperty.call(job.env, 'GRAFANA_MISC_STATS_API_KEY')) {
    hits.push('job.env')
  }
  for (const step of job.steps || []) {
    if (step.env && Object.prototype.hasOwnProperty.call(step.env, 'GRAFANA_MISC_STATS_API_KEY')) {
      hits.push(step.name || step.id || step.uses || 'step')
    }
  }
  return hits
}

function loadTokenModule() {
  const source = `${fs.readFileSync(tokenScript, 'utf8')}\nmodule.exports.__requestIDToken = requestIDToken;\n`
  const sandbox = {
    module: { exports: {} },
    console,
    process,
    fetch: globalThis.fetch,
    AbortSignal,
    URL,
    setTimeout,
    clearTimeout,
  }
  sandbox.globalThis = sandbox
  sandbox.exports = sandbox.module.exports
  vm.runInNewContext(source, sandbox, { filename: tokenScript })
  return sandbox.module.exports
}

const tokenModule = loadTokenModule()

function translateSecrets({ repoSecrets, repository, owner, version }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-translate-'))
  const output = path.join(dir, 'github-output')
  const result = spawnSync('bash', [translateScript], {
    encoding: 'utf8',
    env: {
      PATH: process.env.PATH,
      REPO_SECRETS: repoSecrets || '',
      COMMON_SECRETS: '',
      REPO: repository,
      REPO_OWNER: owner,
      VERSION: version || '',
      GITHUB_OUTPUT: output,
    },
  })
  if (result.status !== 0) {
    throw new Error(`translate-secrets.bash failed: ${result.stderr || result.stdout}`)
  }
  const text = fs.readFileSync(output, 'utf8')
  const match = text.match(/secrets<<EOF\n([\s\S]*?)EOF/)
  if (!match) {
    throw new Error(`translate-secrets.bash wrote no secrets block: ${text}`)
  }
  const records = []
  for (const line of match[1].split('\n')) {
    const trimmed = line.trim().replace(/;$/, '')
    if (!trimmed) {
      continue
    }
    const bar = trimmed.lastIndexOf('|')
    const pathSpec = trimmed.slice(0, bar).trim()
    const outputName = trimmed.slice(bar + 1).trim()
    const parts = pathSpec.split(/\s+/).filter(Boolean)
    if (parts.length !== 2) {
      throw new Error(`unexpected translated secret: ${trimmed}`)
    }
    records.push({ path: parts[0], selector: parts[1], outputName })
  }
  return records
}

function selectKv2(body, selector) {
  // secrets.js builds data."<selector>" and, for a KV v2 payload, prefixes
  // another "data." before evaluating it.
  if (body?.data?.data == null || !Object.prototype.hasOwnProperty.call(body.data.data, selector)) {
    throw new Error(`vault payload has no data.data.${selector}`)
  }
  return body.data.data[selector]
}

function placeholderFor(envName) {
  return `placeholder-for-${envName}`
}

function registerMappings(store, mappings, repository, owner) {
  for (const mapping of mappings) {
    const records = translateSecrets({
      repoSecrets: mapping.repoSecrets,
      repository,
      owner,
      version: mapping.version === 'v2' ? 'v2' : '',
    })
    for (const record of records) {
      const bucket = store.get(record.path) || {}
      bucket[record.selector] = placeholderFor(record.outputName)
      store.set(record.path, bucket)
    }
  }
}

function issueJwt(audience, github, issued) {
  const header = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url')
  const payload = Buffer.from(
    JSON.stringify({
      iss: 'https://token.actions.githubusercontent.com',
      aud: audience,
      repository: github.repository,
      ref: github.ref,
      job_workflow_ref: `${github.repository}/.github/workflows/pr-e2e-tests.yml@${github.ref}`,
    })
  ).toString('base64url')
  const token = `${header}.${payload}.placeholder-signature`
  issued.add(token)
  return token
}

function readJwt(token) {
  const [, payload] = token.split('.')
  return JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'))
}

async function startStandIn(github) {
  const issued = new Set()
  const clientTokens = new Set()
  const secrets = new Map()
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1')
    if (req.method === 'GET' && url.pathname === '/oidc') {
      const header = req.headers.authorization || ''
      if (header !== 'Bearer placeholder-oidc-request-token') {
        res.writeHead(401)
        res.end('missing oidc request token')
        return
      }
      const audience = url.searchParams.get('audience')
      const token = issueJwt(audience, github, issued)
      res.writeHead(200, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ value: token }))
      return
    }

    const chunks = []
    req.on('data', (chunk) => chunks.push(chunk))
    req.on('end', () => {
      if (req.method === 'POST' && url.pathname === '/v1/auth/github-actions-oidc/login') {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')
        const proxy = String(req.headers['proxy-authorization-token'] || '')
        const proxyToken = proxy.startsWith('Bearer ') ? proxy.slice('Bearer '.length) : ''
        const loginClaims = issued.has(body.jwt) ? readJwt(body.jwt) : null
        const proxyClaims = issued.has(proxyToken) ? readJwt(proxyToken) : null
        const roleOk = body.role === 'vault-github-actions' || body.role === `ci-${github.repository_owner}`
        if (
          !loginClaims ||
          !proxyClaims ||
          loginClaims.repository !== github.repository ||
          proxyClaims.aud !== `vault-github-actions-grafana-ops` ||
          !String(loginClaims.aud).startsWith('https://vault-github-actions.grafana-') ||
          !roleOk
        ) {
          res.writeHead(403)
          res.end('vault login rejected')
          return
        }
        const clientToken = `placeholder-vault-client-${clientTokens.size}`
        clientTokens.add(clientToken)
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ auth: { client_token: clientToken, policies: ['ci-read'] } }))
        return
      }

      if (req.method === 'GET' && url.pathname.startsWith('/v1/')) {
        if (!clientTokens.has(req.headers['x-vault-token'])) {
          res.writeHead(403)
          res.end('missing vault token')
          return
        }
        const secretPath = url.pathname.slice('/v1/'.length)
        const bucket = secrets.get(secretPath)
        if (!bucket) {
          res.writeHead(404)
          res.end('not found')
          return
        }
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end(JSON.stringify({ data: { data: bucket } }))
        return
      }

      res.writeHead(404)
      res.end('not found')
    })
  })

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const { port } = server.address()
  return {
    baseUrl: `http://127.0.0.1:${port}`,
    oidcUrl: `http://127.0.0.1:${port}/oidc?job=publish-metrics`,
    secrets,
    close: () => new Promise((resolve) => server.close(resolve)),
  }
}

async function requestJobTokens(standIn, vaultInstance) {
  const env = {
    ACTIONS_ID_TOKEN_REQUEST_URL: standIn.oidcUrl,
    ACTIONS_ID_TOKEN_REQUEST_TOKEN: 'placeholder-oidc-request-token',
    VAULT_INSTANCE: vaultInstance || 'ops',
  }
  let proxyJwt
  const core = {
    setSecret() {},
    setOutput(_name, value) {
      proxyJwt = value
    },
    setFailed(message) {
      throw new Error(message)
    },
    warning() {},
    error() {},
  }
  await tokenModule({ core, env, fetch: globalThis.fetch, sleep: async () => {} })
  const loginAudience = `https://vault-github-actions.grafana-${env.VAULT_INSTANCE}.net`
  const loginJwt = await tokenModule.__requestIDToken({
    core,
    env,
    fetch: globalThis.fetch,
    audience: loginAudience,
  })
  return { proxyJwt, loginJwt, loginAudience }
}

async function readMappedSecrets(standIn, tokens, records, role) {
  const login = await fetch(`${standIn.baseUrl}/v1/auth/github-actions-oidc/login`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      'proxy-authorization-token': `Bearer ${tokens.proxyJwt}`,
    },
    body: JSON.stringify({ jwt: tokens.loginJwt, role }),
  })
  if (!login.ok) {
    throw new Error(`vault login failed: ${login.status} ${await login.text()}`)
  }
  const loginBody = await login.json()
  const clientToken = loginBody.auth.client_token
  const values = {}
  for (const record of records) {
    const response = await fetch(`${standIn.baseUrl}/v1/${record.path}`, {
      headers: { 'x-vault-token': clientToken },
    })
    if (!response.ok) {
      throw new Error(`vault read ${record.path} failed: ${response.status}`)
    }
    const body = await response.json()
    values[record.outputName] = selectKv2(body, record.selector)
  }
  return values
}

function vaultCall(mapping, repository, owner) {
  const version = mapping.version || 'v1'
  const vaultInstance = mapping.vaultInstance || 'ops'
  const records = translateSecrets({
    repoSecrets: mapping.repoSecrets,
    repository,
    owner,
    version: version === 'v2' ? 'v2' : '',
  })
  const role = version === 'v2' ? `ci-${owner}` : 'vault-github-actions'
  return { records, role, vaultInstance, version }
}

function resolveTemplates(value, outputs) {
  if (typeof value !== 'string') {
    return value
  }
  return value.replace(
    /\$\{\{\s*fromJSON\(steps\.([A-Za-z0-9_-]+)\.outputs\.secrets\)\.([A-Za-z0-9_]+)\s*\}\}/g,
    (_match, id, key) => {
      const secrets = outputs[id]?.secrets
      if (!secrets) {
        return ''
      }
      return JSON.parse(secrets)[key] ?? ''
    }
  )
}

function resolveObject(value, outputs) {
  if (Array.isArray(value)) {
    return value.map((item) => resolveObject(item, outputs))
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, resolveObject(item, outputs)]))
  }
  return resolveTemplates(value, outputs)
}

function mappingsFromJob(job) {
  const mappings = []
  for (const step of job.steps || []) {
    if (typeof step.uses === 'string' && step.uses.includes('/get-vault-secrets') && step.with?.repo_secrets) {
      mappings.push({
        repoSecrets: step.with.repo_secrets,
        version: step.with.version || 'v1',
        vaultInstance: step.with.vault_instance || 'ops',
      })
    }
  }
  return mappings
}

async function executeJob(job, { root, github }) {
  const leaks = []
  const outputs = {}
  const mappings = mappingsFromJob(job)
  const canMint = idTokenWrite({ permissions: null }, job) || job.permissions?.['id-token'] === 'write'
  const standIn = await startStandIn(github)
  registerMappings(standIn.secrets, mappings, github.repository, github.repository_owner)
  let publishEnv = null
  let reachedPublish = false
  try {
    for (const { step } of iterateSteps(job, root, github, {}, new Set())) {
      if (typeof step.run === 'string' && step.run.includes('publish-frontend-metrics.mts')) {
        reachedPublish = true
        publishEnv = resolveObject(step.env || {}, outputs)
        continue
      }
      const resolved = step.uses ? resolveActionRef(step.uses, { [parseUses(step.uses)?.ref]: 'branch-tip' }) : null
      if (!resolved) {
        continue
      }
      const resolvedWith = resolveObject(step.with || {}, outputs)
      const resolvedEnv = resolveObject(step.env || {}, outputs)
      if (!resolved.mutable) {
        if (isVaultAction(resolved.name)) {
          const call = vaultCall(
            {
              repoSecrets: resolvedWith.repo_secrets,
              version: resolvedWith.version,
              vaultInstance: resolvedWith.vault_instance,
            },
            github.repository,
            github.repository_owner
          )
          const tokens = canMint ? await requestJobTokens(standIn, call.vaultInstance) : null
          const values = tokens ? await readMappedSecrets(standIn, tokens, call.records, call.role) : {}
          if (step.id) {
            outputs[step.id] = { secrets: JSON.stringify(values) }
          }
        }
        continue
      }

      const taken = {}
      let oidc = false
      if (canMint && mappings.length > 0) {
        // A moving ref is the action source at execution. It can perform the
        // same OIDC exchange and Vault read as the pinned action, for every
        // mapping the workflow file already publishes.
        for (const mapping of mappings) {
          const each = vaultCall(mapping, github.repository, github.repository_owner)
          const tokens = await requestJobTokens(standIn, each.vaultInstance)
          oidc = Boolean(tokens.proxyJwt && tokens.loginJwt)
          Object.assign(taken, await readMappedSecrets(standIn, tokens, each.records, each.role))
        }
      }
      for (const bag of [resolvedWith, resolvedEnv]) {
        for (const [key, value] of Object.entries(bag || {})) {
          if (typeof value === 'string' && value.startsWith('placeholder-for-')) {
            taken[key] = value
          }
        }
      }
      if (oidc || Object.keys(taken).length > 0) {
        const exfilDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-exfil-'))
        const exfil = path.join(exfilDir, 'exfil.json')
        const record = {
          step: step.name || step.id || step.uses,
          uses: step.uses,
          beforePublish: !reachedPublish,
          oidc,
          secretNames: Object.keys(taken),
        }
        fs.writeFileSync(exfil, JSON.stringify({ ...record, secrets: taken }))
        if (!fs.existsSync(exfil)) {
          throw new Error('exfil file was not written')
        }
        fs.rmSync(exfilDir, { recursive: true, force: true })
        leaks.push(record)
      }
      if (isVaultAction(resolved.name) && step.id && Object.keys(taken).length > 0) {
        outputs[step.id] = { secrets: JSON.stringify(taken) }
      }
    }
  } finally {
    await standIn.close()
  }
  return { leaks, outputs, publishEnv }
}

function loadWorkflow(file) {
  return { file, workflow: loadYaml(file) }
}

const workflows = workflowFiles(workflowRoot).map(loadWorkflow)

function jobsWithVault(entry) {
  const found = []
  for (const [jobName, job] of Object.entries(entry.workflow.jobs || {})) {
    if (!job || job.uses) {
      continue
    }
    const vaultSteps = (job.steps || []).filter(
      (step) => typeof step.uses === 'string' && step.uses.includes('/get-vault-secrets')
    )
    if (vaultSteps.length === 0 || !idTokenWrite(entry.workflow, job)) {
      continue
    }
    if (!conditionHolds(job.if, { ...PRODUCTION, github: PRODUCTION })) {
      continue
    }
    found.push({ file: entry.file, jobName, job, vaultSteps })
  }
  return found
}

const vaultJobs = workflows.flatMap(jobsWithVault)

test('a branch ref is resolved again at execution and a commit SHA is not', () => {
  const uses = 'grafana/shared-workflows/actions/get-vault-secrets@main'
  const atPlan = resolveActionRef(uses, { main: 'a'.repeat(40) })
  const atRun = resolveActionRef(uses, { main: 'b'.repeat(40) })
  assert.equal(atPlan.mutable, true)
  assert.notEqual(atPlan.sha, atRun.sha)
  const pinned = resolveActionRef(`grafana/shared-workflows/actions/get-vault-secrets@${'c'.repeat(40)}`, {
    main: 'b'.repeat(40),
  })
  assert.equal(pinned.mutable, false)
  assert.equal(pinned.sha, 'c'.repeat(40))
})

test('pinning get-vault-secrets to a commit SHA keeps the key in the publish step', async () => {
  const sha = '0123456789abcdef0123456789abcdef01234567'
  const job = {
    permissions: { contents: 'read', 'id-token': 'write' },
    steps: [
      {
        id: 'vault-secrets',
        uses: `grafana/shared-workflows/actions/get-vault-secrets@${sha}`,
        with: { repo_secrets: 'GRAFANA_MISC_STATS_API_KEY=grafana-misc-stats:api_key\n' },
      },
      {
        name: 'Extract and publish metrics',
        run: './scripts/ci-frontend-metrics.sh | node .github/workflows/scripts/publish-frontend-metrics.mts',
        env: {
          GRAFANA_MISC_STATS_API_KEY:
            '${{ fromJSON(steps.vault-secrets.outputs.secrets).GRAFANA_MISC_STATS_API_KEY }}',
        },
      },
    ],
  }
  const result = await executeJob(job, { root: repoRoot, github: PRODUCTION })
  assert.deepEqual(result.leaks, [])
  assert.equal(result.publishEnv.GRAFANA_MISC_STATS_API_KEY, placeholderFor('GRAFANA_MISC_STATS_API_KEY'))
})

test('publish-metrics on grafana/grafana main does not give a moving action the stats key or the job OIDC token', async () => {
  const entry = workflows.find((item) => item.file.endsWith(`${path.sep}pr-e2e-tests.yml`))
  assert.ok(entry, 'pr-e2e-tests.yml')
  const job = entry.workflow.jobs['publish-metrics']
  assert.ok(job, 'publish-metrics job')
  const githubOn = { ...PRODUCTION, github: PRODUCTION }
  assert.equal(conditionHolds(job.if, githubOn), true)
  assert.equal(
    conditionHolds(job.if, {
      event_name: 'pull_request',
      repository: 'grafana/grafana',
      ref_name: 'main',
      github: { event_name: 'pull_request', repository: 'grafana/grafana', ref_name: 'main' },
    }),
    false
  )
  assert.equal(
    conditionHolds(job.if, {
      event_name: 'push',
      repository: 'example/grafana',
      ref_name: 'main',
      github: { event_name: 'push', repository: 'example/grafana', ref_name: 'main' },
    }),
    false
  )
  assert.deepEqual(stepsWithApiKeyEnv(job), ['Extract and publish metrics'])
  assert.equal(idTokenWrite(entry.workflow, job), true)

  const result = await executeJob(job, { root: workflowRoot, github: PRODUCTION })
  assert.deepEqual(
    result.leaks,
    [],
    'a moving action ref ran with the job OIDC credential and read the mapped Vault secret before publish-frontend-metrics.mts'
  )
  assert.equal(result.publishEnv.GRAFANA_MISC_STATS_API_KEY, placeholderFor('GRAFANA_MISC_STATS_API_KEY'))
})

for (const site of vaultJobs) {
  const relative = path.relative(workflowRoot, site.file)
  if (relative === path.join('.github', 'workflows', 'pr-e2e-tests.yml') && site.jobName === 'publish-metrics') {
    continue
  }
  test(`${relative} job ${site.jobName} does not give a moving action its Vault secrets or the job OIDC token`, async () => {
    const result = await executeJob(site.job, { root: workflowRoot, github: PRODUCTION })
    assert.deepEqual(
      result.leaks,
      [],
      'a moving action ref ran with the job OIDC credential and read the mapped Vault secret'
    )
    for (const step of site.vaultSteps) {
      if (!step.id) {
        continue
      }
      if (step.if && !conditionHolds(step.if, { ...PRODUCTION, github: PRODUCTION, inputs: {} })) {
        continue
      }
      const secrets = JSON.parse(result.outputs[step.id]?.secrets || '{}')
      for (const record of translateSecrets({
        repoSecrets: step.with.repo_secrets,
        repository: PRODUCTION.repository,
        owner: PRODUCTION.repository_owner,
        version: step.with.version === 'v2' ? 'v2' : '',
      })) {
        assert.equal(secrets[record.outputName], placeholderFor(record.outputName))
      }
    }
  })
}
