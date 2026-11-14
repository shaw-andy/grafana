import { importPluginModuleInSandbox } from './sandboxPluginLoader';

/**
 * Runs plugin code through importPluginModuleInSandbox. Each case creates a script
 * element, sets its source text, and inserts it with one DOM method. A script that
 * reaches the host document runs there and records an iframe tag name on the host window.
 */

const HOST_RESULTS = '__hostScriptResults';

interface HostWindow extends Window {
  __SANDBOX_PLUGIN_CODE?: string;
  __hostScriptResults?: Record<string, string>;
  __runScriptInsertionCases?: () => Promise<CaseResult[]>;
}

export interface CaseResult {
  name: string;
  pluginRan: boolean;
  hostExecuted: boolean;
  connectedToHost: boolean;
  hostValue: string | null;
  error: string | null;
}

interface InsertionCase {
  name: string;
  // Statement that inserts the local `script` element. Plugin code, not host code.
  insert: string;
  // How the plugin sets the script source text before insertion.
  source: 'text' | 'textContent' | 'childText';
}

const INSERTION_CASES: InsertionCase[] = [
  { name: 'Element.append', insert: 'document.body.append(script);', source: 'text' },
  { name: 'Element.append textContent', insert: 'document.body.append(script);', source: 'textContent' },
  { name: 'Element.append child text', insert: 'document.body.append(script);', source: 'childText' },
  {
    name: 'Element.append with a sibling iframe',
    insert:
      'var frame = document.createElement("iframe"); frame.id = script.id + "-frame"; document.body.append(frame, script);',
    source: 'text',
  },
  { name: 'Element.prepend', insert: 'document.body.prepend(script);', source: 'text' },
  { name: 'Element.before', insert: 'document.body.before(script);', source: 'text' },
  { name: 'Element.after', insert: 'document.body.after(script);', source: 'text' },
  { name: 'Element.replaceChildren', insert: 'document.body.replaceChildren(script);', source: 'text' },
  {
    name: 'Element.replaceWith',
    insert:
      'var placeholder = document.createElement("span"); document.body.appendChild(placeholder); placeholder.replaceWith(script);',
    source: 'text',
  },
  {
    name: 'Element.insertAdjacentElement',
    insert: 'document.body.insertAdjacentElement("beforeend", script);',
    source: 'text',
  },
  { name: 'Node.insertBefore', insert: 'document.body.insertBefore(script, null);', source: 'text' },
  {
    name: 'Node.replaceChild',
    insert:
      'var placeholder = document.createElement("span"); document.body.appendChild(placeholder); document.body.replaceChild(script, placeholder);',
    source: 'text',
  },
  {
    name: 'CharacterData.before',
    insert: 'var text = document.createTextNode(""); document.body.appendChild(text); text.before(script);',
    source: 'text',
  },
  {
    name: 'CharacterData.after',
    insert: 'var text = document.createTextNode(""); document.body.appendChild(text); text.after(script);',
    source: 'text',
  },
  {
    name: 'DocumentFragment.append then Node.appendChild',
    insert:
      'var fragment = document.createDocumentFragment(); fragment.append(script); document.body.appendChild(fragment);',
    source: 'text',
  },
  {
    name: 'DocumentFragment.prepend then Node.appendChild',
    insert:
      'var fragment = document.createDocumentFragment(); fragment.prepend(script); document.body.appendChild(fragment);',
    source: 'text',
  },
  // appendChild is the path that already refuses to insert script elements.
  { name: 'Node.appendChild', insert: 'document.body.appendChild(script);', source: 'text' },
  // Runs last: removing <html> drops document.body for every later case.
  {
    name: 'Document.append after removing documentElement',
    insert: 'document.documentElement.remove(); document.append(script);',
    source: 'text',
  },
];

function pluginSource(caseId: string, insertionCase: InsertionCase): string {
  const payload =
    `window.${HOST_RESULTS}=window.${HOST_RESULTS}||{};` +
    `window.${HOST_RESULTS}[${JSON.stringify(caseId)}]=document.createElement("iframe").nodeName;`;

  let assignSource: string;
  if (insertionCase.source === 'text') {
    assignSource = `script.text = ${JSON.stringify(payload)};`;
  } else if (insertionCase.source === 'textContent') {
    assignSource = `script.textContent = ${JSON.stringify(payload)};`;
  } else {
    assignSource = `script.appendChild(document.createTextNode(${JSON.stringify(payload)}));`;
  }

  return `define([], function () {
    var script = document.createElement("script");
    script.id = ${JSON.stringify(caseId)};
    ${assignSource}
    ${insertionCase.insert}
    return { ran: true };
  });`;
}

async function runCase(insertionCase: InsertionCase): Promise<CaseResult> {
  const caseId = `sandbox-script-${insertionCase.name.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}`;
  const host = window as HostWindow;
  host.__SANDBOX_PLUGIN_CODE = pluginSource(caseId, insertionCase);

  let pluginRan = false;
  let error: string | null = null;
  try {
    const exported = await importPluginModuleInSandbox({ pluginId: caseId });
    pluginRan = !!exported && typeof exported === 'object' && (exported as { ran?: boolean }).ran === true;
  } catch (err) {
    error = err instanceof Error ? err.message : String(err);
  }

  const hostValue = host.__hostScriptResults?.[caseId] ?? null;
  return {
    name: insertionCase.name,
    pluginRan,
    hostExecuted: hostValue === 'IFRAME',
    connectedToHost: document.getElementById(caseId) !== null,
    hostValue,
    error,
  };
}

async function runScriptInsertionCases(): Promise<CaseResult[]> {
  const host = window as HostWindow;
  host.__hostScriptResults = {};
  const results: CaseResult[] = [];
  for (const insertionCase of INSERTION_CASES) {
    results.push(await runCase(insertionCase));
  }
  return results;
}

(window as HostWindow).__runScriptInsertionCases = runScriptInsertionCases;
