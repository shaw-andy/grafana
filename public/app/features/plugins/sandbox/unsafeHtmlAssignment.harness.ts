import { getGeneralSandboxDistortionMap } from './distortions';
import { importPluginModuleInSandbox } from './sandboxPluginLoader';

declare global {
  interface Window {
    __viewerMarker: string;
    __messages: Array<{ kind?: string; marker?: string; saw?: string }>;
  }
}

function pluginSource(id: string, body: string): string {
  return `define([], function () {
  var events = [];
  function note(name, status, detail) {
    events.push({ name: name, status: status, detail: String(detail || '') });
    document.documentElement.setAttribute('data-plugin-log-' + ${JSON.stringify(id)}, JSON.stringify(events));
  }
  function markup(marker) {
    var script = "<script>parent.postMessage({kind:'xss',marker:'" + marker + "',saw:String(parent.__viewerMarker)},'*')<\\/script>";
    return '<iframe srcdoc="' + script + '"></iframe>';
  }
  ${body}
  return { plugin: {} };
});
`;
}

const sources: Record<string, string> = {
  'sandbox-xss-elements': pluginSource(
    'elements',
    `
  var host = document.createElement('div');
  host.id = 'attack-host';
  document.body.appendChild(host);

  try {
    var blocked = document.createElement('div');
    host.appendChild(blocked);
    blocked.innerHTML = markup('innerHTML');
    note('innerHTML', 'called', blocked.querySelector('iframe') ? 'iframe-present' : 'no-iframe');
  } catch (e) { note('innerHTML', 'threw', e && e.message); }

  try {
    var el = document.createElement('div');
    host.appendChild(el);
    el.setHTMLUnsafe(markup('element-setHTMLUnsafe'));
    note('element-setHTMLUnsafe', 'called', el.querySelector('iframe') ? 'iframe-present' : 'no-iframe');
  } catch (e2) { note('element-setHTMLUnsafe', 'threw', e2 && e2.message); }

  try {
    var shadowHost = document.createElement('div');
    host.appendChild(shadowHost);
    var root = shadowHost.attachShadow({ mode: 'open' });
    root.setHTMLUnsafe(markup('shadow-setHTMLUnsafe'));
    note('shadow-setHTMLUnsafe', 'called', root.querySelector('iframe') ? 'iframe-present' : 'no-iframe');
  } catch (e3) { note('shadow-setHTMLUnsafe', 'threw', e3 && e3.message); }

  try {
    var shadowHost2 = document.createElement('div');
    host.appendChild(shadowHost2);
    var root2 = shadowHost2.attachShadow({ mode: 'open' });
    root2.innerHTML = markup('shadow-innerHTML');
    note('shadow-innerHTML', 'called', root2.querySelector('iframe') ? 'iframe-present' : 'no-iframe');
  } catch (e4) { note('shadow-innerHTML', 'threw', e4 && e4.message); }

  try {
    var parsed = Document.parseHTMLUnsafe('<div id="parsed">' + markup('parseHTMLUnsafe') + '</div>');
    var node = parsed.getElementById('parsed');
    host.appendChild(node);
    note('parseHTMLUnsafe', 'called', node.querySelector('iframe') ? 'iframe-present' : 'no-iframe');
  } catch (e5) { note('parseHTMLUnsafe', 'threw', e5 && e5.message); }

  try {
    var range = document.createRange();
    range.selectNode(document.body);
    var frag = range.createContextualFragment('<div id="frag">' + markup('createContextualFragment') + '</div>');
    var fragNode = frag.querySelector('#frag');
    host.appendChild(fragNode);
    note('createContextualFragment', 'called', fragNode.querySelector('iframe') ? 'iframe-present' : 'no-iframe');
  } catch (e6) { note('createContextualFragment', 'threw', e6 && e6.message); }

  try {
    new DOMParser().parseFromString('<div>' + markup('domparser') + '</div>', 'text/html');
    note('domparser', 'called', '');
  } catch (e7) { note('domparser', 'threw', e7 && e7.message); }

  try {
    var frame = document.createElement('IFRAME');
    if (!frame || !frame.setAttribute || String(frame.nodeName).toLowerCase() !== 'iframe') {
      note('createElement-insertBefore', 'no-iframe', frame && frame.nodeName);
    } else {
      frame.setAttribute('srcdoc', "<script>parent.postMessage({kind:'xss',marker:'createElement-insertBefore',saw:String(parent.__viewerMarker)},'*')<\\/script>");
      var wrap = document.createElement('div');
      host.appendChild(wrap);
      wrap.insertBefore(frame, null);
      note('createElement-insertBefore', 'called', wrap.querySelector('iframe') ? 'iframe-present' : 'no-iframe');
    }
  } catch (e8) { note('createElement-insertBefore', 'threw', e8 && e8.message); }
`
  ),
  'sandbox-xss-body': pluginSource(
    'body',
    `
  try {
    document.body.setHTMLUnsafe(markup('body-setHTMLUnsafe'));
    note('body-setHTMLUnsafe', 'called', document.body.querySelector('iframe[srcdoc]') ? 'iframe-present' : 'no-iframe');
  } catch (e) { note('body-setHTMLUnsafe', 'threw', e && e.message); }
`
  ),
};

window.__viewerMarker = 'viewer-session-placeholder';
window.__messages = [];
window.addEventListener('message', (event) => {
  window.__messages.push(event.data);
});

const fetched: string[] = [];
window.fetch = (input: RequestInfo | URL) => {
  const url = String(input);
  fetched.push(url);
  const id = Object.keys(sources).find((pluginId) => url.includes(pluginId));
  if (id) {
    return Promise.resolve(new Response(sources[id], { status: 200, headers: { 'Content-Type': 'text/javascript' } }));
  }
  return Promise.resolve(new Response('missing', { status: 404 }));
};

function descriptorValue(proto: object, name: string): unknown {
  const desc = Object.getOwnPropertyDescriptor(proto, name);
  return desc?.value ?? desc?.set ?? desc?.get;
}

async function main() {
  document.cookie = 'session_probe=probe-placeholder; path=/';
  const map = getGeneralSandboxDistortionMap();
  const coverage = {
    elementSetHTMLUnsafe: map.has(descriptorValue(Element.prototype, 'setHTMLUnsafe')),
    shadowSetHTMLUnsafe: map.has(descriptorValue(ShadowRoot.prototype, 'setHTMLUnsafe')),
    parseHTMLUnsafe: map.has(
      descriptorValue(Document, 'parseHTMLUnsafe') ?? descriptorValue(Document.prototype, 'parseHTMLUnsafe')
    ),
    shadowInnerHTML: map.has(descriptorValue(ShadowRoot.prototype, 'innerHTML')),
    elementInnerHTML: map.has(descriptorValue(Element.prototype, 'innerHTML')),
    createContextualFragment: map.has(descriptorValue(Range.prototype, 'createContextualFragment')),
    insertBefore: map.has(descriptorValue(Node.prototype, 'insertBefore')),
    domParser: map.has(descriptorValue(DOMParser.prototype, 'parseFromString')),
  };

  let elementsError = '';
  try {
    await importPluginModuleInSandbox({ pluginId: 'sandbox-xss-elements' });
  } catch (e) {
    elementsError = e instanceof Error ? e.message : String(e);
  }
  await new Promise((resolve) => setTimeout(resolve, 500));
  const elementMessages = window.__messages.slice();

  let bodyError = '';
  try {
    await importPluginModuleInSandbox({ pluginId: 'sandbox-xss-body' });
  } catch (e) {
    bodyError = e instanceof Error ? e.message : String(e);
  }
  await new Promise((resolve) => setTimeout(resolve, 500));

  const frame = document.querySelector('iframe[srcdoc]');
  let parentCookieSeenFromFrame = '';
  if (frame instanceof HTMLIFrameElement && frame.contentWindow) {
    try {
      parentCookieSeenFromFrame = frame.contentWindow.parent.document.cookie;
    } catch (e) {
      parentCookieSeenFromFrame = e instanceof Error ? e.message : String(e);
    }
  }

  const out = {
    coverage,
    fetched,
    elementsError,
    bodyError,
    elementsLog: document.documentElement.getAttribute('data-plugin-log-elements'),
    bodyLog: document.documentElement.getAttribute('data-plugin-log-body'),
    elementMessages,
    messages: window.__messages,
    srcdocIframeCount: document.querySelectorAll('iframe[srcdoc]').length,
    parentCookieSeenFromFrame,
  };
  const pre = document.createElement('pre');
  pre.id = 'out';
  document.body.appendChild(pre);
  pre.textContent = JSON.stringify(out);
}

void main();
