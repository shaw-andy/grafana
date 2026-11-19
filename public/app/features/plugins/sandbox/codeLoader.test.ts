import { PluginType } from '@grafana/data';

import { loadScriptIntoSandbox } from './codeLoader';
import { getGeneralSandboxDistortionMap } from './distortions';
import { getSafeSandboxDomElement } from './documentSandbox';
import { type SandboxEnvironment, type SandboxPluginMeta } from './types';

// jsdom does not implement Worker. The distortion map reads Worker.prototype while it is built.
if (typeof globalThis.Worker === 'undefined') {
  class WorkerStub {
    postMessage() {}
    terminate() {}
  }
  globalThis.Worker = WorkerStub as unknown as typeof Worker;
}

const PLUGIN_ID = 'panel-a';
const PLUGIN_MODULE = 'public/plugins/panel-a/module.js';
const CHUNK_SOURCE = '/* sandboxed chunk */';

type RecordedFetch = {
  url: string;
  credentials: RequestCredentials | undefined;
};

const pluginMeta: SandboxPluginMeta = {
  id: PLUGIN_ID,
  type: PluginType.panel,
  module: PLUGIN_MODULE,
};

function pageUrl(pathnameAndSearch: string): string {
  return new URL(pathnameAndSearch, window.location.href).href;
}

function describeFetch(input: RequestInfo | URL, init?: RequestInit): RecordedFetch {
  if (input instanceof Request) {
    return { url: input.url, credentials: input.credentials };
  }
  const url = input instanceof URL ? input.href : String(input);
  return { url, credentials: init?.credentials };
}

function distortedMethod(
  owner: object,
  methodName: 'appendChild' | 'createElement',
  env: SandboxEnvironment
): (...args: unknown[]) => unknown {
  const map = getGeneralSandboxDistortionMap();
  const method = Object.getOwnPropertyDescriptor(owner, methodName)?.value;
  const factory = map.get(method);
  if (typeof factory !== 'function') {
    throw new Error(`${methodName} distortion missing`);
  }
  return factory(method, pluginMeta, env) as (...args: unknown[]) => unknown;
}

function createSandboxScript(env: SandboxEnvironment): HTMLScriptElement {
  const createElement = distortedMethod(Document.prototype, 'createElement', env);
  const element = createElement.call(document, 'script');
  if (!(element instanceof HTMLScriptElement)) {
    throw new Error('sandboxed createElement did not return a script element');
  }
  return element;
}

function sandboxEnvironment(): SandboxEnvironment & { evaluate: jest.Mock } {
  return { evaluate: jest.fn() } as SandboxEnvironment & { evaluate: jest.Mock };
}

describe('sandboxed plugin script loading', () => {
  let calls: RecordedFetch[];
  let restoreFetch: () => void;

  beforeEach(() => {
    calls = [];
    const originalFetch = global.fetch;
    global.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      calls.push(describeFetch(input, init));
      return new Response(CHUNK_SOURCE, { status: 200 });
    }) as typeof fetch;
    restoreFetch = () => {
      global.fetch = originalFetch;
    };
  });

  afterEach(() => {
    restoreFetch();
  });

  async function expectNoCredentialedOrOffPluginFetch(src: string) {
    const env = sandboxEnvironment();
    const element = createSandboxScript(env);
    element.src = src;
    const exposed = getSafeSandboxDomElement(element, pluginMeta.id);
    expect(exposed).toBe(element);

    const appendChild = distortedMethod(Node.prototype, 'appendChild', env);
    appendChild.call(document.body, exposed);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(element.src).toBe(src);
    expect(calls).toEqual([]);
    expect(env.evaluate).not.toHaveBeenCalled();
  }

  it('does not fetch the logout route when a sandboxed plugin appends that script', async () => {
    await expectNoCredentialedOrOffPluginFetch(pageUrl('/logout'));
  });

  it('does not fetch another same-origin GET route when a sandboxed plugin appends that script', async () => {
    await expectNoCredentialedOrOffPluginFetch(pageUrl('/api/org/users'));
  });

  it('does not fetch a same-host logout URL whose scheme differs from the page', async () => {
    const page = new URL(window.location.href);
    const otherScheme = page.protocol === 'https:' ? 'http:' : 'https:';
    await expectNoCredentialedOrOffPluginFetch(`${otherScheme}//${page.host}/logout`);
  });

  it('does not fetch a sibling plugin script whose id only prefixes this plugin id', async () => {
    await expectNoCredentialedOrOffPluginFetch(pageUrl('/public/plugins/panel-a-extra/812.chunk.js'));
  });

  it('does not fetch a script URL that normalizes outside this plugin asset directory', async () => {
    const element = createSandboxScript(sandboxEnvironment());
    element.src = pageUrl('/public/plugins/panel-a/../../../logout');
    expect(element.src).toBe(pageUrl('/logout'));
    const exposed = getSafeSandboxDomElement(element, pluginMeta.id);
    expect(exposed).toBe(element);

    const env = sandboxEnvironment();
    const appendChild = distortedMethod(Node.prototype, 'appendChild', env);
    appendChild.call(document.body, exposed);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(calls).toEqual([]);
    expect(env.evaluate).not.toHaveBeenCalled();
  });

  it('fetches the script URL it already checked when script.src changes before the request', async () => {
    const chunkUrl = pageUrl('/public/plugins/panel-a/812.chunk.js');
    const logoutUrl = pageUrl('/logout');
    const element = createSandboxScript(sandboxEnvironment());
    let reads = 0;
    Object.defineProperty(element, 'src', {
      configurable: true,
      get() {
        reads += 1;
        return reads === 1 ? chunkUrl : logoutUrl;
      },
    });

    const env = sandboxEnvironment();
    const appendChild = distortedMethod(Node.prototype, 'appendChild', env);
    appendChild.call(document.body, element);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(reads).toBeGreaterThan(0);
    expect(calls).toEqual([{ url: chunkUrl, credentials: 'omit' }]);
    expect(env.evaluate).toHaveBeenCalledWith(CHUNK_SOURCE);
  });

  it('fetches a script under this plugin asset directory with credentials omitted', async () => {
    const chunkUrl = pageUrl('/public/plugins/panel-a/812.chunk.js?v=1');
    const env = sandboxEnvironment();
    const element = createSandboxScript(env);
    element.src = chunkUrl;
    const exposed = getSafeSandboxDomElement(element, pluginMeta.id);
    expect(exposed).toBe(element);
    expect(element.src).toBe(chunkUrl);

    const appendChild = distortedMethod(Node.prototype, 'appendChild', env);
    appendChild.call(document.body, exposed);
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(calls).toEqual([{ url: chunkUrl, credentials: 'omit' }]);
    expect(env.evaluate).toHaveBeenCalledWith(CHUNK_SOURCE);
  });

  it('does not fetch a logout URL passed straight to the sandbox script loader', async () => {
    const logoutUrl = pageUrl('/logout');
    const env = sandboxEnvironment();
    await loadScriptIntoSandbox(logoutUrl, env).catch(() => undefined);
    expect(calls).toEqual([]);
    expect(env.evaluate).not.toHaveBeenCalled();
  });
});
