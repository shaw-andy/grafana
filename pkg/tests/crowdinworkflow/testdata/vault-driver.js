'use strict';

// Stand-in driver for the vault read performed by
// grafana/shared-workflows/actions/get-vault-secrets and
// hashicorp/vault-action@892a26828f195e65540a40b4768ae4571f51ebfc.
//
// get-id-token.js is the action's own script (blob 99a7f9563e2ff4c57799e5859c226fe4668f1964).
// parseSecretsInput, getSecrets, selectData, and selectAndAppendResults are the
// vault-action functions at that SHA (src/action.js and src/secrets.js).
// jsonata is the 2.0.4 release locked by that action's package-lock.json.
// The HTTP body is a KV v2 read of the key the workflow names. No live Vault call.

const fs = require('fs');
const getIDToken = require(process.env.GET_ID_TOKEN);
const jsonata = require(process.env.JSONATA_MODULE);

const WILDCARD_UPPERCASE = '*';
const WILDCARD = '**';

const core = {
  outputs: {},
  debug() {},
  error(message) {
    console.error(message);
  },
  warning(message) {
    console.error(message);
  },
  setFailed(message) {
    throw new Error(message);
  },
  setSecret() {},
  setOutput(name, value) {
    this.outputs[name] = value;
  },
  getInput() {
    return 'false';
  },
};

function normalizeOutputKey(dataKey, upperCase = false) {
  let outputKey = dataKey
    .replaceAll('.', '__')
    .replace(new RegExp('-', 'g'), '')
    .replace(/[^\p{L}\p{N}_-]/gu, '');
  if (upperCase) {
    outputKey = outputKey.toUpperCase();
  }
  return outputKey;
}

// hashicorp/vault-action src/action.js parseSecretsInput at 892a268.
function parseSecretsInput(secretsInput) {
  if (!secretsInput) {
    return [];
  }

  const secrets = secretsInput
    .split(';')
    .filter((key) => !!key)
    .map((key) => key.trim())
    .filter((key) => key.length !== 0);

  const output = [];
  for (const secret of secrets) {
    let pathSpec = secret;
    let outputVarName = null;

    const renameSigilIndex = secret.lastIndexOf('|');
    if (renameSigilIndex > -1) {
      pathSpec = secret.substring(0, renameSigilIndex).trim();
      outputVarName = secret.substring(renameSigilIndex + 1).trim();

      if (outputVarName.length < 1) {
        throw Error(`You must provide a value when mapping a secret to a name. Input: "${secret}"`);
      }
    }

    const pathParts = pathSpec
      .split(/\s+/)
      .map((part) => part.trim())
      .filter((part) => part.length !== 0);

    if (pathParts.length !== 2) {
      throw Error(`You must provide a valid path and key. Input: "${secret}"`);
    }

    const [path, selectorQuoted] = pathParts;

    const selectorAst = jsonata(selectorQuoted).ast();
    const selector = selectorQuoted.replace(new RegExp('"', 'g'), '');

    if (
      selector !== WILDCARD &&
      selector !== WILDCARD_UPPERCASE &&
      (selectorAst.type !== 'path' || selectorAst.steps[0].stages) &&
      selectorAst.type !== 'string' &&
      !outputVarName
    ) {
      throw Error(`You must provide a name for the output key when using json selectors. Input: "${secret}"`);
    }

    let envVarName = outputVarName;
    if (!outputVarName) {
      outputVarName = normalizeOutputKey(selector);
      envVarName = normalizeOutputKey(selector, true);
    }

    output.push({
      path,
      envVarName,
      outputVarName,
      selector,
    });
  }
  return output;
}

// hashicorp/vault-action src/secrets.js selectData at 892a268.
async function selectData(data, selector) {
  const ata = jsonata(selector);
  let result = JSON.stringify(await ata.evaluate(data));

  if (
    !result &&
    ((ata.ast().type === 'path' && ata.ast()['steps'].length === 1) || ata.ast().type === 'string') &&
    selector !== 'data' &&
    'data' in data
  ) {
    result = JSON.stringify(await jsonata(`data.${selector}`).evaluate(data));
  } else if (!result) {
    throw Error(`Unable to retrieve result for ${selector}. No match data was found. Double check your Key or Selector.`);
  }

  if (result.startsWith('"')) {
    result = JSON.parse(result);
  }
  return result;
}

// hashicorp/vault-action src/secrets.js selectAndAppendResults at 892a268.
const selectAndAppendResults = async (selector, body, cachedResponse, secretRequest, results) => {
  if (!selector.includes('.')) {
    selector = '"' + selector + '"';
  }
  selector = 'data.' + selector;

  if (body.data['data'] != undefined) {
    selector = 'data.' + selector;
  }

  const value = await selectData(body, selector);
  return [
    ...results,
    {
      request: secretRequest,
      value,
      cachedResponse,
    },
  ];
};

// hashicorp/vault-action src/secrets.js getSecrets at 892a268, without the wildcard branch.
async function getSecrets(secretRequests, client) {
  const responseCache = new Map();
  let results = [];

  for (const secretRequest of secretRequests) {
    let { path, selector } = secretRequest;
    const requestPath = `v1/${path.replace(/^\/+/, '')}`;
    let body;
    let cachedResponse = false;
    if (responseCache.has(requestPath)) {
      body = responseCache.get(requestPath);
      cachedResponse = true;
    } else {
      const result = await client.get(requestPath);
      body = result.body;
      responseCache.set(requestPath, body);
    }

    body = JSON.parse(body);
    if (selector === WILDCARD || selector === WILDCARD_UPPERCASE) {
      throw new Error('wildcard selectors are not used by the crowdin workflows');
    }
    results = await selectAndAppendResults(selector, body, cachedResponse, secretRequest, results);
  }

  return results;
}

// actions/runner FileCommandManager output parser at v2.338.2.
function parseOutputFile(text) {
  const outputs = {};
  let index = 0;
  const readLine = () => {
    if (index >= text.length) {
      return { line: null, newline: null };
    }
    const nl = text.indexOf('\n', index);
    if (nl < 0) {
      const line = text.slice(index);
      index = text.length;
      return { line, newline: null };
    }
    const line = text.slice(index, nl);
    index = nl + 1;
    return { line, newline: '\n' };
  };

  let current = readLine();
  while (current.line !== null) {
    const line = current.line;
    if (line) {
      const equalsIndex = line.indexOf('=');
      const heredocIndex = line.indexOf('<<');
      if (equalsIndex >= 0 && (heredocIndex < 0 || equalsIndex < heredocIndex)) {
        outputs[line.slice(0, equalsIndex)] = line.slice(equalsIndex + 1);
      } else if (heredocIndex >= 0 && (equalsIndex < 0 || heredocIndex < equalsIndex)) {
        const key = line.slice(0, heredocIndex);
        const delimiter = line.slice(heredocIndex + 2);
        if (!key || !delimiter) {
          throw new Error(`Invalid format '${line}'`);
        }
        const startIndex = index;
        let endIndex = index;
        let temp = readLine();
        while (temp.line !== delimiter) {
          if (temp.line === null) {
            throw new Error(`Matching delimiter not found '${delimiter}'`);
          }
          if (temp.newline === null) {
            throw new Error('EOF marker missing new line');
          }
          endIndex = index - temp.newline.length;
          temp = readLine();
        }
        outputs[key] = endIndex > startIndex ? text.slice(startIndex, endIndex) : '';
      } else {
        throw new Error(`Invalid format '${line}'`);
      }
    }
    current = readLine();
  }
  return outputs;
}

async function main() {
  const outputFile = process.argv[2];
  const vaultBody = process.argv[3];
  if (!outputFile || !vaultBody) {
    throw new Error('usage: vault-driver.js <github-output-file> <vault-body-json>');
  }

  const coreToken = Object.create(core);
  coreToken.outputs = {};
  await getIDToken({
    core: coreToken,
    env: process.env,
    fetch: async (url) => {
      const audience = 'vault-github-actions-grafana-ops';
      const expected = `audience=${encodeURIComponent(audience)}`;
      if (!String(url).includes(expected)) {
        throw new Error(`OIDC request URL did not include ${expected}`);
      }
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        json: async () => ({ value: 'placeholder-oidc-jwt' }),
      };
    },
    sleep: async () => {},
  });
  if (coreToken.outputs['github-jwt'] !== 'placeholder-oidc-jwt') {
    throw new Error('get-id-token.js did not return the OIDC token');
  }

  const translated = parseOutputFile(fs.readFileSync(outputFile, 'utf8'));
  const requests = parseSecretsInput(translated.secrets);
  const client = {
    get: async () => ({ body: vaultBody }),
  };
  const results = await getSecrets(requests, client);
  // action.js exportSecrets writes setOutput and skips exportVariable when exportEnv is false.
  for (const result of results) {
    const value = `${result.value}`;
    for (const line of value.replace(/\r/g, '').split('\n')) {
      if (line.length > 0) {
        core.setSecret(line);
      }
    }
    core.setOutput(result.request.outputVarName, value);
  }
  for (const [name, value] of Object.entries(core.outputs)) {
    process.stdout.write(`${name}=${value}\n`);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
