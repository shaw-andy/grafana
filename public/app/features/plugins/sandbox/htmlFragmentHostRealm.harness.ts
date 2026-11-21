import { PluginSignatureStatus, PluginSignatureType, PluginType } from '@grafana/data';
import { config, setBackendSrv, type BackendSrv } from '@grafana/runtime';

import { contextSrv } from 'app/core/services/context_srv';

import { importPluginModuleInSandbox } from './sandboxPluginLoader';
import { shouldLoadPluginInFrontendSandbox } from './sandboxPluginLoaderRegistry';

/**
 * Host-realm proof: a handler compiled by the browser from an HTML attribute
 * calls createElement('iframe'). The sandbox distortion replaces that call with
 * a document fragment. The host document's native createElement returns an
 * iframe element. The probe text is therefore IFRAME only when the handler ran
 * as host-page script.
 */
type Sink = {
  id: string;
  /** Plugin statements. `markup` is the HTML string and `probeId` is the probe element id. */
  source: string;
  /** When true, run this sink in its own document because it can replace the page. */
  destructive?: boolean;
};

function handlerFor(probeId: string): string {
  // sessionStorage survives document.open/writeln replacing the page.
  return `try{sessionStorage.setItem('${probeId}',document.createElement('iframe').nodeName)}catch(e){}var el=document.getElementById('${probeId}');if(el)el.textContent=document.createElement('iframe').nodeName`;
}

function img(probeId: string): string {
  return `<img src="x" alt="" onerror="${handlerFor(probeId)}">`;
}

function details(probeId: string): string {
  return `<details open ontoggle="${handlerFor(probeId)}"></details>`;
}

const sinks: Sink[] = [
  {
    id: 'createContextualFragment-appendChild',
    source: `document.body.appendChild(document.createRange().createContextualFragment(markup));`,
  },
  {
    id: 'createContextualFragment-child-appendChild',
    source: `var fragment=document.createRange().createContextualFragment(markup);document.body.appendChild(fragment.firstChild);`,
  },
  {
    id: 'new-Range-createContextualFragment-appendChild',
    source: `document.body.appendChild(new Range().createContextualFragment(markup));`,
  },
  {
    id: 'createContextualFragment-insertBefore',
    source: `document.body.insertBefore(document.createRange().createContextualFragment(markup), null);`,
  },
  {
    id: 'createContextualFragment-replaceChild',
    source: `var slot=document.createElement('span');document.body.appendChild(slot);document.body.replaceChild(document.createRange().createContextualFragment(markup), slot);`,
  },
  {
    id: 'createContextualFragment-append',
    source: `document.body.append(document.createRange().createContextualFragment(markup));`,
  },
  {
    id: 'createContextualFragment-prepend',
    source: `document.body.prepend(document.createRange().createContextualFragment(markup));`,
  },
  {
    id: 'createContextualFragment-before',
    source: `var slot=document.createElement('span');document.body.appendChild(slot);slot.before(document.createRange().createContextualFragment(markup));`,
  },
  {
    id: 'createContextualFragment-after',
    source: `var slot=document.createElement('span');document.body.appendChild(slot);slot.after(document.createRange().createContextualFragment(markup));`,
  },
  {
    id: 'createContextualFragment-insertAdjacentElement',
    source: `document.body.insertAdjacentElement('beforeend', document.createRange().createContextualFragment(markup).firstElementChild);`,
  },
  {
    id: 'DOMParser-parseFromString-onerror',
    source: `var parsed=new DOMParser().parseFromString(markup,'text/html');document.body.appendChild(parsed.body.firstChild);`,
  },
  {
    id: 'DOMParser-parseFromString-ontoggle',
    source: `var parsed=new DOMParser().parseFromString(alternate,'text/html');document.body.appendChild(parsed.body.firstChild);`,
  },
  {
    id: 'innerHTML-onerror',
    source: `var slot=document.createElement('div');document.body.appendChild(slot);slot.innerHTML=markup;`,
  },
  {
    id: 'innerHTML-ontoggle',
    source: `var slot=document.createElement('div');document.body.appendChild(slot);slot.innerHTML=alternate;`,
  },
  {
    id: 'outerHTML-ontoggle',
    source: `var slot=document.createElement('div');document.body.appendChild(slot);slot.outerHTML=alternate;`,
  },
  {
    id: 'insertAdjacentHTML-ontoggle',
    source: `var slot=document.createElement('div');document.body.appendChild(slot);slot.insertAdjacentHTML('beforeend', alternate);`,
  },
  {
    id: 'template-innerHTML-ontoggle',
    source: `var template=document.createElement('template');template.innerHTML=alternate;document.body.appendChild(template.content.firstChild);`,
  },
  {
    id: 'setAttribute-onerror',
    source: `var image=document.createElement('img');image.setAttribute('onerror', handler);image.alt='';image.src='x';document.body.appendChild(image);`,
  },
  {
    id: 'setAttributeNS-onerror',
    source: `var image=document.createElement('img');image.setAttributeNS(null,'onerror', handler);image.alt='';image.src='x';document.body.appendChild(image);`,
  },
  {
    id: 'execCommand-insertHTML',
    source: `var slot=document.createElement('div');slot.contentEditable='true';document.body.appendChild(slot);slot.focus();document.execCommand('insertHTML', false, markup);`,
  },
  {
    id: 'parseHTMLUnsafe',
    source: `if (typeof document.parseHTMLUnsafe!=='function') { skipped=true; } else { var parsed=document.parseHTMLUnsafe(markup); document.body.appendChild(parsed.body.firstChild); }`,
  },
  {
    id: 'setHTMLUnsafe',
    source: `var slot=document.createElement('div');document.body.appendChild(slot);if (typeof slot.setHTMLUnsafe!=='function') { skipped=true; } else { slot.setHTMLUnsafe(markup); }`,
  },
  {
    id: 'setHTML',
    source: `var slot=document.createElement('div');document.body.appendChild(slot);if (typeof slot.setHTML!=='function') { skipped=true; } else { slot.setHTML(markup); }`,
  },
  {
    id: 'shadow-root-innerHTML',
    source: `var slot=document.createElement('div');document.body.appendChild(slot);slot.attachShadow({mode:'open'}).innerHTML=markup;`,
  },
  {
    id: 'setAttributeNode-onerror',
    source: `var image=document.createElement('img');var attr=document.createAttribute('onerror');attr.value=handler;image.setAttributeNode(attr);image.alt='';image.src='x';document.body.appendChild(image);`,
  },
  {
    id: 'document-write',
    destructive: true,
    source: `document.write(markup);`,
  },
  {
    id: 'document-writeln',
    destructive: true,
    source: `document.writeln(markup);`,
  },
];

type SinkResult = {
  id: string;
  probe: string;
  directIframeNodeName: string;
  benign: string;
  error: string;
  skipped: boolean;
  sandboxSelected: boolean;
};

declare global {
  interface Window {
    __htmlFragmentResults?: SinkResult[];
    __runHtmlFragmentProbe?: () => Promise<SinkResult[]>;
  }
}

function pluginSource(sink: Sink, probeId: string): string {
  const markup = img(probeId);
  const alternate = details(probeId);
  const handler = handlerFor(probeId);
  return `define([], function () {
    var markup = ${JSON.stringify(markup)};
    var alternate = ${JSON.stringify(alternate)};
    var handler = ${JSON.stringify(handler)};
    var skipped = false;
    var error = '';
    try {
      ${sink.source}
    } catch (e) {
      error = String(e && e.message ? e.message : e);
    }
    var direct = document.createElement('span');
    direct.id = ${JSON.stringify(`direct-${sink.id}`)};
    direct.textContent = document.createElement('iframe').nodeName;
    document.body.appendChild(direct);
    var benign = document.createElement('span');
    benign.id = ${JSON.stringify(`benign-${sink.id}`)};
    benign.textContent = 'benign';
    document.body.appendChild(benign);
    var note = document.createElement('span');
    note.id = ${JSON.stringify(`error-${sink.id}`)};
    note.textContent = skipped ? 'skipped' : error;
    document.body.appendChild(note);
    return {};
  });`;
}

function installFetch(sources: Map<string, string>) {
  const realFetch = window.fetch.bind(window);
  window.fetch = async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
    for (const [pluginId, source] of sources) {
      if (url.includes(`/plugins/${pluginId}/module.js`)) {
        return new Response(source, {
          status: 200,
          headers: { 'Content-Type': 'application/javascript' },
        });
      }
    }
    const settingsMatch = url.match(/\/api\/plugins\/([^/]+)\/settings/);
    if (settingsMatch) {
      const pluginId = decodeURIComponent(settingsMatch[1]);
      return new Response(
        JSON.stringify({
          id: pluginId,
          name: pluginId,
          type: PluginType.datasource,
          module: `/public/plugins/${pluginId}/module.js`,
          baseUrl: `/public/plugins/${pluginId}`,
          signature: PluginSignatureStatus.valid,
          signatureType: PluginSignatureType.community,
          info: {
            author: { name: 'probe' },
            version: '1.0.0',
            updated: '',
            links: [],
          },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      );
    }
    return realFetch(input, init);
  };
}

function pluginMeta(pluginId: string) {
  return {
    id: pluginId,
    name: pluginId,
    type: PluginType.datasource,
    module: `/public/plugins/${pluginId}/module.js`,
    baseUrl: `/public/plugins/${pluginId}`,
    signature: PluginSignatureStatus.valid,
    signatureType: PluginSignatureType.community,
    info: {
      author: { name: 'probe' },
      version: '1.0.0',
      updated: '',
      links: [],
    },
  };
}

function installBackend() {
  // The real backend service is created by the Grafana server. This probe only
  // needs the plugin settings document that the sandbox eligibility check reads.
  const backend = {
    get: async (url: string) => {
      const settingsMatch = url.match(/\/api\/plugins\/([^/]+)\/settings/);
      if (settingsMatch) {
        return pluginMeta(decodeURIComponent(settingsMatch[1]));
      }
      throw new Error(`unexpected backend request ${url}`);
    },
    delete: async () => {
      throw new Error('unexpected backend delete');
    },
    post: async () => {
      throw new Error('unexpected backend post');
    },
    patch: async () => {
      throw new Error('unexpected backend patch');
    },
    put: async () => {
      throw new Error('unexpected backend put');
    },
    request: async () => {
      throw new Error('unexpected backend request');
    },
    fetch: () => {
      throw new Error('unexpected backend fetch');
    },
    datasourceRequest: async () => {
      throw new Error('unexpected datasource request');
    },
  } as unknown as BackendSrv;
  setBackendSrv(backend);
}

function registerPlugins(pluginIds: string[]) {
  config.enableFrontendSandboxForPlugins = pluginIds;
  for (const pluginId of pluginIds) {
    config.datasources[pluginId] = {
      id: 1,
      uid: pluginId,
      type: pluginId,
      name: pluginId,
        meta: pluginMeta(pluginId),
      jsonData: {},
    } as (typeof config.datasources)[string];
  }
}

async function readResult(sink: Sink, sandboxSelected: boolean): Promise<SinkResult> {
  const probe = document.getElementById(`probe-${sink.id}`);
  const direct = document.getElementById(`direct-${sink.id}`);
  const benign = document.getElementById(`benign-${sink.id}`);
  const note = document.getElementById(`error-${sink.id}`);
  return {
    id: sink.id,
    probe: probe?.textContent ?? '',
    directIframeNodeName: direct?.textContent ?? '',
    benign: benign?.textContent ?? '',
    error: note?.textContent === 'skipped' ? '' : (note?.textContent ?? ''),
    skipped: note?.textContent === 'skipped',
    sandboxSelected,
  };
}

async function runSink(sink: Sink): Promise<SinkResult> {
  const pluginId = `probe-${sink.id}`;
  const probeId = `probe-${sink.id}`;
  const probe = document.createElement('div');
  probe.id = probeId;
  document.body.appendChild(probe);

  let sandboxSelected = false;
  let gateError = '';
  try {
    sandboxSelected = await shouldLoadPluginInFrontendSandbox({ pluginId });
  } catch (e) {
    gateError = e instanceof Error ? e.message : String(e);
  }

  if (sandboxSelected) {
    try {
      await importPluginModuleInSandbox({ pluginId });
    } catch (e) {
      gateError = e instanceof Error ? e.message : String(e);
    }
  }

  await new Promise((resolve) => window.setTimeout(resolve, 400));
  const result = await readResult(sink, sandboxSelected);
  if (!result.error && gateError) {
    result.error = gateError;
  }
  return result;
}

async function run(): Promise<SinkResult[]> {
  if (!contextSrv.isSignedIn) {
    throw new Error('sandbox eligibility requires a signed-in user');
  }
  const only = new URLSearchParams(window.location.search).get('sink');
  const selected = sinks.filter((sink) => (only ? sink.id === only : !sink.destructive));
  const sources = new Map<string, string>();
  for (const sink of selected) {
    sources.set(`probe-${sink.id}`, pluginSource(sink, `probe-${sink.id}`));
  }
  installFetch(sources);
  installBackend();
  registerPlugins([...sources.keys()]);

  const results: SinkResult[] = [];
  for (const sink of selected) {
    results.push(await runSink(sink));
  }
  window.__htmlFragmentResults = results;
  return results;
}

window.__runHtmlFragmentProbe = run;
void run();
