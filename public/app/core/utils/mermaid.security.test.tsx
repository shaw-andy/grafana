import { waitFor } from '@testing-library/react';
import { useRef } from 'react';
import { render } from 'test/test-utils';

import { createTheme, renderMarkdown, textUtil, type GrafanaTheme2 } from '@grafana/data';
import { setTestFlags } from '@grafana/test-utils/unstable';
import { type RepositoryView } from 'app/api/clients/provisioning/v0alpha1';
import { useMermaidDiagrams } from 'app/core/hooks/useMermaidDiagrams';
import { rewriteRelativeMarkdownLinks } from 'app/features/provisioning/utils/markdownLinks';
import { TextMode } from 'app/plugins/panel/text/panelcfg.gen';
import { TextNGHtmlView } from 'app/plugins/panel/text/v2/TextNGHtmlView';
import { transformContent } from 'app/plugins/panel/text/v2/utils';

import { renderMermaidDiagrams } from './mermaid';

const theme: GrafanaTheme2 = createTheme();

/**
 * Git Sync folder the readme panel resolves links against. The diagram source
 * sits in a fenced code block, so this rewrite does not touch it; the test
 * still runs the same helper the panel runs.
 */
const repository: RepositoryView = {
  name: 'manifests',
  target: 'folder',
  title: 'Manifests',
  type: 'github',
  url: 'https://github.com/example/manifests',
  branch: 'main',
  workflows: [],
};

const LOGOUT_NODE = 'flowchart TD\n  A@{ img: "/logout", label: "x", pos: "b", w: 40, h: 40, constraint: "on" }';
const ORG_NODE =
  'flowchart TD\n  B@{ img: "/profile/switch-org/2", label: "y", pos: "b", w: 40, h: 40, constraint: "on" }';

interface ImageHit {
  url: string;
}

let hits: ImageHit[] = [];
let restoreRecorder: (() => void) | undefined;

/**
 * Mermaid assigns a flowchart image URL to an HTML image, and to an SVG
 * <image>, while it is drawing. Logout and organization-switch responses are
 * not images, so decoding rejects after that assignment. The recorder keeps
 * the assignment and rejects decode so the test observes the request the
 * browser would already have started.
 */
function installImageRecorder() {
  hits = [];
  const note = (url: unknown) => {
    if (typeof url === 'string' && url.length > 0) {
      hits.push({ url });
    }
  };

  const imageProto = HTMLImageElement.prototype;
  const srcDesc = Object.getOwnPropertyDescriptor(imageProto, 'src');
  if (srcDesc?.set && srcDesc.get) {
    Object.defineProperty(imageProto, 'src', {
      configurable: true,
      enumerable: srcDesc.enumerable ?? true,
      get() {
        return srcDesc.get!.call(this);
      },
      set(value: string) {
        note(value);
        srcDesc.set!.call(this, value);
      },
    });
  }

  const originalDecode = imageProto.decode;
  imageProto.decode = function decode() {
    return Promise.reject(new DOMException('The source image could not be decoded.', 'EncodingError'));
  };

  const originalSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function setAttribute(name: string, value: string) {
    const tag = this.tagName.toLowerCase();
    if ((tag === 'img' || tag === 'image') && (name === 'src' || name === 'href')) {
      note(value);
    }
    return originalSetAttribute.call(this, name, value);
  };

  const originalSetAttributeNS = Element.prototype.setAttributeNS;
  Element.prototype.setAttributeNS = function setAttributeNS(namespace: string | null, name: string, value: string) {
    const tag = this.tagName.toLowerCase();
    const local = name.includes(':') ? name.slice(name.indexOf(':') + 1) : name;
    if ((tag === 'img' || tag === 'image') && (local === 'src' || local === 'href')) {
      note(value);
    }
    return originalSetAttributeNS.call(this, namespace, name, value);
  };

  restoreRecorder = () => {
    if (srcDesc?.set && srcDesc.get) {
      Object.defineProperty(imageProto, 'src', srcDesc);
    }
    imageProto.decode = originalDecode;
    Element.prototype.setAttribute = originalSetAttribute;
    Element.prototype.setAttributeNS = originalSetAttributeNS;
    restoreRecorder = undefined;
  };
}

function sameOriginPaths(): string[] {
  return hits.map((hit) => {
    try {
      return new URL(hit.url, window.location.href).pathname;
    } catch {
      return hit.url;
    }
  });
}

function fence(source: string): string {
  return `<pre><code class="language-mermaid">${source}</code></pre>`;
}

function readmeHtml(markdown: string): string {
  const html = renderMarkdown(markdown, { noSanitize: true });
  const rewritten = rewriteRelativeMarkdownLinks(html, { repository, baseDirInRepo: 'dashboards/team' });
  return textUtil.sanitize(rewritten);
}

async function renderFence(source: string) {
  const container = document.createElement('div');
  container.innerHTML = fence(source);
  document.body.appendChild(container);
  await renderMermaidDiagrams(container, theme, new AbortController().signal);
}

function Host({ html }: { html: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useMermaidDiagrams(ref, html);
  return <div ref={ref} dangerouslySetInnerHTML={{ __html: html }} />;
}

beforeEach(() => {
  document.body.innerHTML = '';
  installImageRecorder();
  setTestFlags({});
});

afterEach(() => {
  restoreRecorder?.();
  document.body.innerHTML = '';
  setTestFlags({});
});

describe('mermaid diagram image requests', () => {
  it('does not request the logout path from a flowchart image node', async () => {
    await renderFence(LOGOUT_NODE);

    expect(sameOriginPaths().filter((path) => path === '/logout')).toEqual([]);
  });

  it('does not request the organization switch path from a flowchart image node', async () => {
    await renderFence(ORG_NODE);

    expect(sameOriginPaths().filter((path) => path === '/profile/switch-org/2')).toEqual([]);
  });

  it('does not request logout when a <pre class="mermaid"> block carries an image node', async () => {
    const container = document.createElement('div');
    const pre = document.createElement('pre');
    pre.className = 'mermaid';
    pre.textContent = LOGOUT_NODE;
    container.appendChild(pre);
    document.body.appendChild(container);

    await renderMermaidDiagrams(container, theme, new AbortController().signal);

    expect(sameOriginPaths().filter((path) => path === '/logout')).toEqual([]);
  });

  it('does not request logout for a Git Sync folder readme that contains the image node', async () => {
    const markdown = ['```mermaid', LOGOUT_NODE, '```'].join('\n');
    const html = readmeHtml(markdown);
    const container = document.createElement('div');
    container.innerHTML = html;
    document.body.appendChild(container);

    await renderMermaidDiagrams(container, theme, new AbortController().signal);

    expect(sameOriginPaths().filter((path) => path === '/logout')).toEqual([]);
  });

  it('does not request logout when the folder readme hook renders the diagram', async () => {
    const markdown = ['```mermaid', ORG_NODE, '```'].join('\n');
    const html = readmeHtml(markdown);

    render(<Host html={html} />);

    await waitFor(() => {
      const settled =
        hits.length > 0 ||
        document.querySelector('.mermaid-diagram') !== null ||
        document.querySelector('.mermaid-diagram-error') !== null;
      expect(settled).toBe(true);
    });

    expect(sameOriginPaths().filter((path) => path === '/profile/switch-org/2')).toEqual([]);
  });

  it('does not request logout from the text panel when its new features are enabled', async () => {
    setTestFlags({ 'text.newFeatures': true });
    const markdown = ['```mermaid', LOGOUT_NODE, '```'].join('\n');
    const html = transformContent(TextMode.Markdown, markdown, false);

    render(<TextNGHtmlView html={html} />);

    await waitFor(() => {
      const settled =
        hits.length > 0 ||
        document.querySelector('.mermaid-diagram') !== null ||
        document.querySelector('.mermaid-diagram-error') !== null;
      expect(settled).toBe(true);
    });

    expect(sameOriginPaths().filter((path) => path === '/logout')).toEqual([]);
  });

  it('does not request logout from an HTML-mode text panel diagram', async () => {
    setTestFlags({ 'text.newFeatures': true });
    const html = transformContent(TextMode.HTML, `<pre class="mermaid">${LOGOUT_NODE}</pre>`, false);

    render(<TextNGHtmlView html={html} />);

    await waitFor(() => {
      const settled =
        hits.length > 0 ||
        document.querySelector('.mermaid-diagram') !== null ||
        document.querySelector('.mermaid-diagram-error') !== null;
      expect(settled).toBe(true);
    });

    expect(sameOriginPaths().filter((path) => path === '/logout')).toEqual([]);
  });
});
