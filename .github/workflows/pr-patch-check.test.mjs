/**
 * Spec for the same-repository patch-conflict gate in pr-patch-check.yml.
 *
 * These tests execute the job's actions/github-script sources the way
 * callAsyncFunction does (new AsyncFunction over the script text). They fail
 * while the wait step treats a different workflow run as this pull request.
 *
 * The GitHub REST stand-in follows the shapes this workflow's client uses:
 * - createWorkflowDispatch is a 204 with an empty body
 *   (@octokit/openapi-types 19.0.0, the version locked by actions/github-script@v8).
 * - listWorkflowRuns filters branch and the created date qualifier, then
 *   returns one page. Pages are newest created_at first, which is the order
 *   the public list endpoint returned for grafana/grafana workflow runs.
 * - A run's name and display_title are the same string. Live runs whose
 *   workflow sets run-name report that text in both fields. This stand-in
 *   builds that string as `${src_repo} ${src_ref}` because the wait step
 *   only ever finds a run when name contains both, and a successful
 *   production run for head ref alexk/kind-registry did find one.
 * - head_sha is the security-patch-actions revision the workflow was
 *   dispatched on, not the pull request commit. Every run in one scenario
 *   shares it, so a comparison against the pull request SHA cannot identify
 *   the dispatch.
 * - head_branch is the dispatch ref (`main`).
 *
 * Untested, because they do not select a workflow run by name:
 * - dispatch-job-fork (forks are marked success on purpose)
 * - .github/workflows/sync-mirror-event.yml
 * - .github/workflows/create-security-patch-from-security-mirror.yml
 */
import assert from 'node:assert/strict';
import { describe, test } from 'node:test';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);

const workflowPath = fileURLToPath(new URL('./pr-patch-check.yml', import.meta.url));
const policyPath = fileURLToPath(new URL('../../.policy.yml', import.meta.url));

const WORKFLOW_HEAD_SHA = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
const PR_COMMIT_SHA = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
const MERGE_SHA = 'cccccccccccccccccccccccccccccccccccccccc';

describe('pr-patch-check dispatch correlation', { concurrency: false }, () => {
  test('policy-bot treats a success conclusion of this workflow as the merge gate', () => {
    const policy = fs.readFileSync(policyPath, 'utf8');
    const rule = policy.slice(policy.indexOf('name: Workflow .github/workflows/pr-patch-check.yml'));
    assert.ok(rule.startsWith('name: Workflow .github/workflows/pr-patch-check.yml'));
    assert.match(rule, /conclusions:[\s\S]*?- success/);
    assert.match(rule, /- \.github\/workflows\/pr-patch-check\.yml/);
  });

  test('does not succeed from an older run whose name merely contains the branch', async () => {
    const result = await runJob({
      headRef: 'grafana',
      hiddenForFirstNLists: 1,
      dispatchedConclusion: 'failure',
      preexisting: [
        {
          name: 'grafana/grafana other-branch',
          ageMs: 30_000,
          status: 'completed',
          conclusion: 'success',
        },
      ],
    });

    assert.equal(result.succeeded, false, result.detail);
    assert.equal(result.successRunId, null);
  });

  test('does not succeed from a newer run whose name merely contains the branch', async () => {
    const result = await runJob({
      headRef: 'feature',
      dispatchedConclusion: 'failure',
      alongside(add, ours) {
        add({
          name: 'grafana/grafana feature-extra',
          created_at: new Date(Date.parse(ours.created_at) + 1000).toISOString(),
          status: 'completed',
          conclusion: 'success',
        });
      },
    });

    assert.equal(result.succeeded, false, result.detail);
    assert.equal(result.successRunId, null);
  });

  test('does not succeed from an already successful run of this same branch', async () => {
    const result = await runJob({
      headRef: 'feature-long-name',
      hiddenForFirstNLists: 1,
      dispatchedConclusion: 'failure',
      preexisting: [
        {
          name: 'grafana/grafana feature-long-name',
          ageMs: 20_000,
          status: 'completed',
          conclusion: 'success',
        },
      ],
    });

    assert.equal(result.succeeded, false, result.detail);
    assert.equal(result.successRunId, null);
  });

  test('succeeds when the run created for this dispatch succeeds', async () => {
    const result = await runJob({
      headRef: 'feature-long-name',
      dispatchedConclusion: 'success',
    });

    assert.equal(result.succeeded, true, result.detail);
    assert.equal(result.successRunId, result.dispatchedRunId);
  });

  test('does not fail this pull request because a different substring run failed', async () => {
    const result = await runJob({
      headRef: 'feature',
      dispatchedConclusion: 'success',
      alongside(add, ours) {
        add({
          name: 'grafana/grafana feature-extra',
          created_at: new Date(Date.parse(ours.created_at) + 1000).toISOString(),
          status: 'completed',
          conclusion: 'failure',
        });
      },
    });

    assert.equal(result.succeeded, true, result.detail);
    assert.equal(result.successRunId, result.dispatchedRunId);
  });

  test('does not switch to a later substring match after it has identified this dispatch', async () => {
    const result = await runJob({
      headRef: 'feature-long-name',
      dispatchedConclusion: 'failure',
      afterFirstRead(add, ours) {
        add({
          name: 'grafana/grafana x-feature-long-name-y',
          created_at: new Date(Date.parse(ours.created_at) + 1000).toISOString(),
          status: 'completed',
          conclusion: 'success',
        });
      },
    });

    assert.equal(result.succeeded, false, result.detail);
    assert.equal(result.successRunId, null);
    assert.ok(result.fetchedRunIds.includes(result.dispatchedRunId));
  });

  test('does not switch to a later run that reuses this branch name', async () => {
    const result = await runJob({
      headRef: 'feature-long-name',
      dispatchedConclusion: 'failure',
      afterFirstRead(add, ours) {
        add({
          name: ours.name,
          created_at: new Date(Date.parse(ours.created_at) + 1000).toISOString(),
          status: 'completed',
          conclusion: 'success',
        });
      },
    });

    assert.equal(result.succeeded, false, result.detail);
    assert.equal(result.successRunId, null);
    assert.ok(result.fetchedRunIds.includes(result.dispatchedRunId));
  });
});

async function runJob(scenario) {
  const workflow = fs.readFileSync(workflowPath, 'utf8');
  const job = parseDispatchJob(workflow);
  const scripts = job.steps.filter((step) => String(step.uses || '').includes('actions/github-script') && step.with?.script);
  assert.ok(scripts.length >= 2, 'dispatch-job must contain the dispatch and wait scripts');

  const restoreClock = installFakeClock(Date.parse('2026-11-14T12:00:00.000Z'));
  const envSnapshot = { ...process.env };
  const exitSnapshot = process.exitCode;
  const store = [];
  let seq = 8000;
  let listCalls = 0;
  let dispatchedRun = null;
  let injected = false;
  const fetchedRunIds = [];
  const failed = [];
  const stepOutputs = {};
  const persistedExports = {};

  const add = (partial) => {
    const id = ++seq;
    const created_at = partial.created_at;
    const run = {
      id,
      name: partial.name,
      display_title: partial.name,
      head_branch: 'main',
      status: partial.status ?? 'in_progress',
      conclusion: partial.conclusion ?? null,
      created_at,
      updated_at: created_at,
      html_url: `https://github.com/grafana/security-patch-actions/actions/runs/${id}`,
      inProgressReads: partial.inProgressReads ?? 0,
      reads: 0,
    };
    store.push(run);
    return run;
  };

  for (const preexisting of scenario.preexisting ?? []) {
    add({
      ...preexisting,
      created_at: new Date(Date.now() - preexisting.ageMs).toISOString(),
    });
  }

  const github = {
    rest: {
      actions: {
        async createWorkflowDispatch(params) {
          assert.equal(params.owner, 'grafana');
          assert.equal(params.repo, 'security-patch-actions');
          assert.equal(params.workflow_id, 'test-patches-event.yml');
          assert.equal(params.ref, 'main');
          advanceFakeClock(1);
          dispatchedRun = add({
            name: `${params.inputs.src_repo} ${params.inputs.src_ref}`,
            created_at: new Date().toISOString(),
            status: 'completed',
            conclusion: scenario.dispatchedConclusion,
            inProgressReads: scenario.inProgressReads ?? 1,
          });
          if (scenario.alongside) {
            scenario.alongside(add, dispatchedRun);
          }
          return { status: 204, data: null, url: '', headers: {} };
        },
        async listWorkflowRuns(params) {
          if (++listCalls > 500) {
            throw new Error('listWorkflowRuns polled more than 500 times');
          }
          if (
            params.owner !== 'grafana' ||
            params.repo !== 'security-patch-actions' ||
            params.workflow_id !== 'test-patches-event.yml'
          ) {
            return { status: 200, data: { total_count: 0, workflow_runs: [] }, headers: {} };
          }
          const matched = store.filter((run) => {
            if (
              dispatchedRun &&
              run.id === dispatchedRun.id &&
              listCalls <= (scenario.hiddenForFirstNLists ?? 0)
            ) {
              return false;
            }
            if (params.branch && run.head_branch !== params.branch) {
              return false;
            }
            if (params.created && !createdMatches(params.created, run.created_at)) {
              return false;
            }
            return true;
          });
          matched.sort((a, b) => {
            const byTime = Date.parse(b.created_at) - Date.parse(a.created_at);
            return byTime || b.id - a.id;
          });
          const perPage = params.per_page ?? 30;
          const page = params.page ?? 1;
          const start = (page - 1) * perPage;
          return {
            status: 200,
            headers: {},
            data: {
              total_count: matched.length,
              workflow_runs: matched.slice(start, start + perPage).map(publicRun),
            },
          };
        },
        async getWorkflowRun(params) {
          const run = store.find((item) => item.id === params.run_id);
          if (!run) {
            throw new Error(`missing workflow run ${params.run_id}`);
          }
          fetchedRunIds.push(run.id);
          run.reads += 1;
          if (!injected && scenario.afterFirstRead && dispatchedRun && run.id === dispatchedRun.id) {
            injected = true;
            scenario.afterFirstRead(add, dispatchedRun);
          }
          const visible =
            run.reads <= run.inProgressReads
              ? { ...run, status: 'in_progress', conclusion: null }
              : run;
          return { status: 200, headers: {}, data: publicRun(visible) };
        },
      },
    },
  };

  const ctx = {
    github: {
      head_ref: scenario.headRef,
      base_ref: 'main',
      repository: 'grafana/grafana',
      sha: MERGE_SHA,
      event: {
        sender: { login: 'contributor' },
        pull_request: {
          head: {
            sha: PR_COMMIT_SHA,
            repo: { fork: false },
          },
        },
      },
    },
    steps: stepOutputs,
  };

  let succeeded = false;
  let error = null;
  try {
    const jobEnv = interpolateMap(job.env, ctx);
    for (const step of scripts) {
      const outputs = {};
      const core = {
        setOutput(name, value) {
          outputs[name] = toCommandValue(value);
        },
        setFailed(message) {
          failed.push(toCommandValue(message));
          process.exitCode = 1;
        },
        exportVariable(name, value) {
          const converted = toCommandValue(value);
          persistedExports[name] = converted;
          process.env[name] = converted;
        },
        info() {},
        warning() {},
        error() {},
        debug() {},
        isDebug() {
          return false;
        },
      };
      const stepEnv = interpolateMap(step.env ?? {}, ctx);
      for (const [key, value] of Object.entries({ ...jobEnv, ...persistedExports, ...stepEnv })) {
        process.env[key] = value;
      }
      await callAsyncFunction(
        {
          require,
          __original_require__: require,
          github,
          octokit: github,
          context: ctx,
          core,
          exec: {},
          glob: {},
          io: {},
        },
        step.with.script
      );
      if (step.id) {
        stepOutputs[step.id] = { outputs };
      }
    }
    succeeded = failed.length === 0;
  } catch (err) {
    error = err;
    succeeded = false;
  } finally {
    process.exitCode = exitSnapshot;
    for (const key of Object.keys(process.env)) {
      delete process.env[key];
    }
    Object.assign(process.env, envSnapshot);
    restoreClock();
  }

  const successRunId = succeeded ? lastCompletedSuccess(fetchedRunIds, store) : null;
  return {
    succeeded,
    successRunId,
    dispatchedRunId: dispatchedRun ? dispatchedRun.id : null,
    fetchedRunIds,
    detail: error ? String(error.stack || error) : failed.join('\n'),
  };
}

function lastCompletedSuccess(fetchedRunIds, store) {
  let found = null;
  for (const id of fetchedRunIds) {
    const run = store.find((item) => item.id === id);
    if (run && run.reads > run.inProgressReads && run.status === 'completed' && run.conclusion === 'success') {
      found = id;
    }
  }
  return found;
}

function publicRun(run) {
  return {
    id: run.id,
    name: run.name,
    display_title: run.display_title,
    node_id: `run-${run.id}`,
    head_branch: run.head_branch,
    head_sha: WORKFLOW_HEAD_SHA,
    path: '.github/workflows/test-patches-event.yml',
    event: 'workflow_dispatch',
    status: run.status,
    conclusion: run.conclusion,
    created_at: run.created_at,
    updated_at: run.updated_at,
    html_url: run.html_url,
    run_attempt: 1,
  };
}

// Query-for-dates: `>` is strictly after the timestamp. The workflow sends `>${iso}`.
function createdMatches(query, createdAt) {
  const match = /^(>=|<=|>|<)(.+)$/.exec(query);
  if (!match) {
    return Date.parse(createdAt) === Date.parse(query);
  }
  const actual = Date.parse(createdAt);
  const bound = Date.parse(match[2]);
  switch (match[1]) {
    case '>':
      return actual > bound;
    case '>=':
      return actual >= bound;
    case '<':
      return actual < bound;
    case '<=':
      return actual <= bound;
    default:
      return false;
  }
}

function toCommandValue(input) {
  if (input === null || input === undefined) {
    return '';
  }
  if (typeof input === 'string') {
    return input;
  }
  return JSON.stringify(input);
}

// actions/github-script src/async-function.ts at tag v8 (ed597411d8f924073f98dfc5c65a23a2325f34cd).
function callAsyncFunction(args, source) {
  const AsyncFunction = Object.getPrototypeOf(async () => null).constructor;
  const fn = new AsyncFunction(...Object.keys(args), source);
  return fn(...Object.values(args));
}

let fakeNow = 0;

function installFakeClock(startMs) {
  const RealDate = Date;
  const realSetTimeout = globalThis.setTimeout;
  fakeNow = startMs;
  class FakeDate extends RealDate {
    constructor(...args) {
      if (args.length === 0) {
        super(fakeNow);
      } else {
        super(...args);
      }
    }
    static now() {
      return fakeNow;
    }
  }
  FakeDate.parse = RealDate.parse;
  FakeDate.UTC = RealDate.UTC;
  globalThis.Date = FakeDate;
  globalThis.setTimeout = (fn, ms, ...rest) => {
    advanceFakeClock(ms ?? 0);
    return realSetTimeout(fn, 0, ...rest);
  };
  return () => {
    globalThis.Date = RealDate;
    globalThis.setTimeout = realSetTimeout;
  };
}

function advanceFakeClock(ms) {
  fakeNow += ms;
}

function interpolateMap(map, ctx) {
  const out = {};
  for (const [key, value] of Object.entries(map)) {
    out[key] = interpolate(value, ctx);
  }
  return out;
}

function interpolate(value, ctx) {
  return String(value).replace(/\$\{\{\s*([^}]+?)\s*\}\}/g, (_, expr) => {
    const parts = expr.trim().split('.');
    let cur = ctx;
    for (const part of parts) {
      if (cur == null || typeof cur !== 'object') {
        return '';
      }
      cur = cur[part];
    }
    return cur == null ? '' : String(cur);
  });
}

function parseDispatchJob(text) {
  const lines = text.split('\n');
  const start = lines.findIndex((line) => line === '  dispatch-job:');
  if (start < 0) {
    throw new Error('dispatch-job not found');
  }
  let end = lines.length;
  for (let i = start + 1; i < lines.length; i++) {
    if (/^  [^ \n]/.test(lines[i])) {
      end = i;
      break;
    }
  }
  const jobLines = lines.slice(start, end);
  const envIdx = jobLines.findIndex((line) => line === '    env:');
  const stepsIdx = jobLines.findIndex((line) => line === '    steps:');
  return {
    env: envIdx >= 0 ? parseBlock(jobLines, envIdx, 6) : {},
    steps: parseSteps(jobLines.slice(stepsIdx + 1)),
  };
}

function parseSteps(lines) {
  const steps = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/^      - /.test(lines[i])) {
      continue;
    }
    const stepLines = [lines[i]];
    for (let j = i + 1; j < lines.length; j++) {
      if (/^      - /.test(lines[j])) {
        break;
      }
      stepLines.push(lines[j]);
      i = j;
    }
    steps.push(parseStep(stepLines));
  }
  return steps;
}

function parseStep(lines) {
  const step = { env: {}, with: {} };
  const first = lines[0].replace(/^      - /, '');
  const firstKey = first.match(/^([^:]+):\s*(.*)$/);
  if (firstKey) {
    step[firstKey[1]] = unquote(firstKey[2].trim());
  }
  for (let i = 1; i < lines.length; i++) {
    if (indentOf(lines[i]) !== 8 || lines[i].trim() === '') {
      continue;
    }
    const match = lines[i].match(/^        ([^:]+):\s*(.*)$/);
    if (!match) {
      continue;
    }
    if (match[1] === 'env' || match[1] === 'with') {
      step[match[1]] = parseBlock(lines, i, 10);
    } else {
      step[match[1]] = unquote(match[2].trim());
    }
  }
  return step;
}

function parseBlock(lines, keyIdx, childIndent) {
  const map = {};
  for (let i = keyIdx + 1; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim() === '') {
      continue;
    }
    const indent = indentOf(line);
    if (indent < childIndent) {
      break;
    }
    if (indent !== childIndent) {
      continue;
    }
    const match = line.match(/^ +([^:]+):\s*(.*)$/);
    if (!match) {
      continue;
    }
    const raw = match[2].trim();
    if (raw === '|' || raw === '|-' || raw === '>' || raw === '>-') {
      const block = [];
      let blockIndent = null;
      for (let j = i + 1; j < lines.length; j++) {
        const blockLine = lines[j];
        if (blockLine.trim() === '') {
          block.push('');
          i = j;
          continue;
        }
        const blockIndentNow = indentOf(blockLine);
        if (blockIndent === null) {
          blockIndent = blockIndentNow;
        }
        if (blockIndentNow < blockIndent) {
          break;
        }
        block.push(blockLine.slice(blockIndent));
        i = j;
      }
      map[match[1]] = block.join('\n');
    } else {
      map[match[1]] = unquote(raw);
    }
  }
  return map;
}

function indentOf(line) {
  return line.match(/^ */)[0].length;
}

function unquote(value) {
  if (
    (value.startsWith('"') && value.endsWith('"')) ||
    (value.startsWith("'") && value.endsWith("'"))
  ) {
    return value.slice(1, -1);
  }
  return value;
}
