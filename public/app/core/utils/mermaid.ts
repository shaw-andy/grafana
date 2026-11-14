import { css, cx } from '@emotion/css';
import type { Mermaid, MermaidConfig } from 'mermaid';

import { textUtil, type GrafanaTheme2 } from '@grafana/data';
import { t } from '@grafana/i18n';

export const DIAGRAM_CLASS = 'mermaid-diagram';
const DIAGRAM_ERROR_CLASS = 'mermaid-diagram-error';

// Also matches already-rendered diagrams, so a theme change redraws them instead of leaving stale colors.
const MERMAID_SELECTOR = `code.language-mermaid, pre.mermaid, .${DIAGRAM_CLASS}`;
const SOURCE_ATTR = 'data-mermaid-source';

// Render ids have to be unique document-wide, not just per panel.
let diagramSeq = 0;

export async function renderMermaidDiagrams(container: HTMLElement, theme: GrafanaTheme2, signal: AbortSignal) {
  const diagrams = Array.from(container.querySelectorAll(MERMAID_SELECTOR), (block) => {
    // A fence keeps the source in the <code>, but the <pre> is what gets replaced.
    const target = block.tagName === 'CODE' ? (block.parentElement ?? block) : block;
    // textContent un-escapes marked's `--&gt;` back to `-->` for free.
    return { source: target.getAttribute(SOURCE_ATTR) ?? target.textContent ?? '', target };
  });

  if (diagrams.length === 0) {
    return;
  }

  const styles = getStyles(theme);

  let mermaid: Mermaid;
  try {
    ({ default: mermaid } = await import(/* webpackChunkName: "mermaid" */ 'mermaid'));
    mermaid.initialize(getMermaidConfig(theme, Object.keys(mermaid.mermaidAPI.defaultConfig)));
  } catch (error) {
    diagrams.forEach(({ source, target }) => markFailed(target, source, asError(error), styles));
    return;
  }

  for (const { source, target } of diagrams) {
    const result = await renderDiagram(mermaid, source);
    if (signal.aborted) {
      return;
    }

    if (typeof result === 'string') {
      const diagram = document.createElement('div');
      diagram.className = cx(DIAGRAM_CLASS, styles.diagram);
      diagram.setAttribute(SOURCE_ATTR, source);
      diagram.innerHTML = textUtil.sanitizeSVGContent(result);
      // A recovered redraw takes the earlier message with it.
      clearError(target);
      target.replaceWith(diagram);
    } else {
      markFailed(target, source, result, styles);
    }
  }
}

async function renderDiagram(mermaid: Mermaid, source: string): Promise<string | Error> {
  try {
    // suppressErrors so a syntax error is a false, not a throw that leaves
    // mermaid's own unthemed error graphic behind.
    if (!(await mermaid.parse(source, { suppressErrors: true }))) {
      return new Error(t('mermaid.invalid-syntax', 'invalid diagram syntax'));
    }
    // Mermaid requests these while it draws, with the viewer's cookies, so they
    // have to be refused before render; sanitizing the SVG afterwards is too late.
    const diagram = await mermaid.mermaidAPI.getDiagramFromText(source);
    if (referencesImage(diagram.db) || referencesCssResource(source)) {
      return new Error(t('mermaid.external-resource', 'diagrams cannot load images or other external resources'));
    }
    const { svg } = await mermaid.render(`mermaid-diagram-${++diagramSeq}`, source);
    return svg;
  } catch (error) {
    return asError(error);
  }
}

interface DiagramModel {
  // Flowchart nodes declared with `@{ img: ... }`.
  getVertices?: () => unknown;
  // Sequence participants given `properties` with an `icon`.
  getActors?: () => unknown;
}

/** The only diagram features mermaid turns into an image request. */
function referencesImage(db: object): boolean {
  const model: DiagramModel = db;
  const vertices = valuesOf<{ img?: unknown }>(model.getVertices?.());
  const actors = valuesOf<{ properties?: { icon?: unknown } }>(model.getActors?.());
  return vertices.some((vertex) => Boolean(vertex?.img)) || actors.some((actor) => Boolean(actor?.properties?.icon));
}

function valuesOf<T>(collection: unknown): T[] {
  if (collection instanceof Map) {
    return Array.from(collection.values());
  }
  return collection && typeof collection === 'object' ? Object.values(collection) : [];
}

// A function name only counts when it is not the tail of a longer identifier.
const CSS_RESOURCE = /(?:^|[^a-z0-9_-])(?:-[a-z0-9]+-)?(?:url|src|image|image-set)\(|@import/;

/**
 * Style statements (`classDef`, `style`, `UpdateElementStyle`, ...) reach the page as
 * inline styles and stylesheet rules, where a CSS url() is fetched with the viewer's
 * cookies. Mermaid turns `#40;`-style escapes into HTML entities and the browser then
 * resolves both those and CSS backslash escapes, so the check looks through each layer.
 */
function referencesCssResource(source: string): boolean {
  return [source, unescapeBackslashes(source)].some((text) => {
    const decoded = decodeEntities(text);
    return [decoded, decodeCssEscapes(decoded)].some((css) => {
      const lower = css.toLowerCase();
      return CSS_RESOURCE.test(lower) || CSS_RESOURCE.test(lower.replace(/\s+/g, ''));
    });
  });
}

/** Undoes the `\x` and `\uXXXX` string escapes some diagram grammars apply. */
function unescapeBackslashes(text: string): string {
  return text.replace(/\\(?:u([0-9a-f]{4})|([\s\S]))/gi, (_, hex: string | undefined, char: string) =>
    hex ? String.fromCharCode(parseInt(hex, 16)) : char
  );
}

function decodeEntities(text: string): string {
  // An inert document: nothing parsed into it can start a request.
  const textarea = document.implementation.createHTMLDocument('').createElement('textarea');
  let decoded = text;
  for (let pass = 0; pass < 4; pass++) {
    const html = decoded
      .replace(/(?<!&)#(\d+);/g, '&#$1;')
      .replace(/(?<!&)#([a-z]\w*);/gi, '&$1;')
      .replace(/</g, '&lt;');
    textarea.innerHTML = html;
    const next = textarea.value;
    if (next === decoded) {
      break;
    }
    decoded = next;
  }
  return decoded;
}

function decodeCssEscapes(css: string): string {
  return css.replace(/\\(?:([0-9a-f]{1,6})[ \t\n\r\f]?|([\s\S]))/gi, (_, hex: string | undefined, char: string) => {
    if (!hex) {
      return char === '\n' ? '' : char;
    }
    const codePoint = parseInt(hex, 16);
    return codePoint > 0 && codePoint <= 0x10ffff && (codePoint < 0xd800 || codePoint > 0xdfff)
      ? String.fromCodePoint(codePoint)
      : '\ufffd';
  });
}

function markFailed(target: Element, source: string, error: Error, styles: Styles) {
  const text = t('mermaid.render-error', 'Diagram error: {{message}}', { message: error.message });

  // A rendered diagram belongs to the old theme, so a failed redraw swaps it back to the source.
  const anchor = target.classList.contains(DIAGRAM_CLASS) ? restoreSource(target, source) : target;

  // A theme-change redraw may hit the same failure again; update the existing message instead of duplicating it.
  const previous = anchor.previousElementSibling;
  if (previous?.classList.contains(DIAGRAM_ERROR_CLASS)) {
    previous.className = cx(DIAGRAM_ERROR_CLASS, styles.error);
    previous.textContent = text;
    return;
  }

  const message = document.createElement('div');
  message.className = cx(DIAGRAM_ERROR_CLASS, styles.error);
  // Announce the failure to screen readers without stealing focus.
  message.setAttribute('role', 'status');
  message.textContent = text;
  anchor.insertAdjacentElement('beforebegin', message);
}

/** Restores the source in a form a later redraw picks up again. */
function restoreSource(diagram: Element, source: string): Element {
  const pre = document.createElement('pre');
  pre.className = 'mermaid';
  pre.setAttribute(SOURCE_ATTR, source);
  pre.textContent = source;
  diagram.replaceWith(pre);
  return pre;
}

function clearError(target: Element) {
  const previous = target.previousElementSibling;
  if (previous?.classList.contains(DIAGRAM_ERROR_CLASS)) {
    previous.remove();
  }
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

type Styles = ReturnType<typeof getStyles>;

// The renderer styles what it creates, so every consumer gets a themed, responsive diagram for free.
function getStyles(theme: GrafanaTheme2) {
  return {
    diagram: css({
      // The diagram stands in for a <pre>, which had block margins of its own.
      margin: theme.spacing(2, 0),
      svg: {
        maxWidth: '100%',
        height: 'auto',
      },
    }),
    error: css({
      color: theme.colors.error.text,
      fontSize: theme.typography.bodySmall.fontSize,
      marginBottom: theme.spacing(0.5),
    }),
  };
}

function getMermaidConfig(theme: GrafanaTheme2, configKeys: string[]): MermaidConfig {
  return {
    startOnLoad: false,
    securityLevel: 'strict',
    // Front matter and %%{init}%% directives may not override anything set here: several
    // settings (htmlLabels, themeCSS, fontFamily, themeVariables, dompurifyConfig) would
    // otherwise let diagram source put HTML or CSS that loads URLs into the page.
    secure: configKeys,
    // Mermaid sanitizes label HTML with this and inserts it into the page while it
    // draws, including for diagrams that ignore htmlLabels. CSS url() is refused
    // before render instead, because built-in icons need their style attributes.
    dompurifyConfig: {
      FORBID_TAGS: ['style', 'img', 'image', 'picture', 'source', 'video', 'audio', 'track', 'input', 'use', 'feimage'],
      FORBID_ATTR: ['src', 'srcset', 'href', 'xlink:href', 'poster', 'background', 'data'],
    },
    // sanitizeSVGContent drops <foreignObject>, where mermaid puts HTML labels,
    // so the shapes would survive with no text in them.
    htmlLabels: false,
    flowchart: { htmlLabels: false, useMaxWidth: true },
    // We report failures ourselves; never let mermaid inject its own error graphic.
    suppressErrorRendering: true,
    theme: 'base',
    fontFamily: theme.typography.fontFamily,
    themeVariables: {
      darkMode: theme.isDark,
      background: theme.colors.background.primary,
      mainBkg: theme.colors.background.secondary,
      primaryColor: theme.colors.background.secondary,
      primaryTextColor: theme.colors.text.primary,
      primaryBorderColor: theme.colors.border.medium,
      secondaryColor: theme.colors.background.canvas,
      tertiaryColor: theme.colors.background.elevated,
      lineColor: theme.colors.border.strong,
      textColor: theme.colors.text.primary,
      titleColor: theme.colors.text.maxContrast,
      nodeBorder: theme.colors.border.medium,
      clusterBkg: theme.colors.background.canvas,
      clusterBorder: theme.colors.border.weak,
      edgeLabelBackground: theme.colors.background.primary,
      fontSize: `${theme.typography.fontSize}px`,
    },
  };
}
