import { forbiddenElements } from './constants';

/**
 * Helpers used by the sandbox distortions to keep plugin-provided markup and nodes from running
 * script outside the sandbox. They run on values handed over by plugin code, so DOM state is read
 * through the native accessors captured here rather than through properties a plugin could shadow.
 */

const XHTML_NAMESPACE = 'http://www.w3.org/1999/xhtml';
const SVG_NAMESPACE = 'http://www.w3.org/2000/svg';
const MATHML_NAMESPACE = 'http://www.w3.org/1998/Math/MathML';
// namespaces whose elements run inline event handler attributes
const scriptableNamespaces = [XHTML_NAMESPACE, SVG_NAMESPACE, MATHML_NAMESPACE];

export class ForbiddenElementError extends Error {
  constructor(public readonly element: string) {
    super('<' + element + '> is not allowed in sandboxed plugins');
  }
}

function getNativeGetter(proto: object | undefined, property: string): Function | undefined {
  return proto ? Object.getOwnPropertyDescriptor(proto, property)?.get : undefined;
}

function getNativeSetter(proto: object | undefined, property: string): Function | undefined {
  return proto ? Object.getOwnPropertyDescriptor(proto, property)?.set : undefined;
}

const nativeNodeType = getNativeGetter(Node.prototype, 'nodeType');
const nativeParentNode = getNativeGetter(Node.prototype, 'parentNode');
const nativeOwnerDocument = getNativeGetter(Node.prototype, 'ownerDocument');
const nativeRemoveChild = Node.prototype.removeChild;
const nativeLocalName = getNativeGetter(Element.prototype, 'localName');
const nativeNamespaceURI = getNativeGetter(Element.prototype, 'namespaceURI');
const nativeShadowRoot = getNativeGetter(Element.prototype, 'shadowRoot');
const nativeGetAttributeNames = Element.prototype.getAttributeNames;
const nativeGetAttribute = Element.prototype.getAttribute;
const nativeRemoveAttribute = Element.prototype.removeAttribute;
const nativeInnerHTMLGetter = getNativeGetter(Element.prototype, 'innerHTML');
const nativeInnerHTMLSetter = getNativeSetter(Element.prototype, 'innerHTML');
const nativeOuterHTMLGetter = getNativeGetter(Element.prototype, 'outerHTML');
const nativeShadowRootHost = getNativeGetter(
  typeof ShadowRoot === 'undefined' ? undefined : ShadowRoot.prototype,
  'host'
);
const nativeTemplateContent = getNativeGetter(
  typeof HTMLTemplateElement === 'undefined' ? undefined : HTMLTemplateElement.prototype,
  'content'
);
const nativeContentType = getNativeGetter(Document.prototype, 'contentType');
const nativeDoctype = getNativeGetter(Document.prototype, 'doctype');
const nativeDocumentElement = getNativeGetter(Document.prototype, 'documentElement');
const nativeCreateElementNS = Document.prototype.createElementNS;
const nativeCreateTreeWalker = Document.prototype.createTreeWalker;
const nativeTreeWalkerNextNode = TreeWalker.prototype.nextNode;
const nativeParseFromString = DOMParser.prototype.parseFromString;

export function getNodeType(value: unknown): number | undefined {
  if (!nativeNodeType || typeof value !== 'object' || value === null) {
    return undefined;
  }
  try {
    return nativeNodeType.call(value);
  } catch (e) {
    // not a DOM node
    return undefined;
  }
}

export function isNode(value: unknown): value is Node {
  return getNodeType(value) !== undefined;
}

export function isElementNode(value: unknown): value is Element {
  return getNodeType(value) === Node.ELEMENT_NODE;
}

function isDocumentNode(value: unknown): value is Document {
  return getNodeType(value) === Node.DOCUMENT_NODE;
}

export function getElementLocalName(element: Node): string {
  return String(nativeLocalName?.call(element) ?? '').toLowerCase();
}

function getNamespace(element: Node): string | null {
  return nativeNamespaceURI?.call(element) ?? null;
}

function isForbiddenElement(element: Element): boolean {
  return getNamespace(element) === XHTML_NAMESPACE && forbiddenElements.includes(getElementLocalName(element));
}

function isScriptElement(element: Element): boolean {
  const namespace = getNamespace(element);
  return getElementLocalName(element) === 'script' && (namespace === XHTML_NAMESPACE || namespace === SVG_NAMESPACE);
}

// a <base> element changes where every relative script URL of the page is loaded from
function isBaseElement(element: Element): boolean {
  return getNamespace(element) === XHTML_NAMESPACE && getElementLocalName(element) === 'base';
}

export function isHTMLScriptElement(node: unknown): node is HTMLScriptElement {
  return isElementNode(node) && getElementLocalName(node) === 'script' && getNamespace(node) === XHTML_NAMESPACE;
}

function isJavaScriptURL(value: string): boolean {
  // the URL parser ignores control characters and spaces when reading the scheme
  // eslint-disable-next-line no-control-regex
  return value
    .replace(/[\u0000-\u0020]/g, '')
    .toLowerCase()
    .includes('javascript:');
}

function getUnsafeAttributeNames(element: Element): string[] {
  if (!scriptableNamespaces.includes(getNamespace(element) ?? '')) {
    return [];
  }
  const unsafe: string[] = [];
  for (const name of nativeGetAttributeNames.call(element)) {
    const lowerCaseName = name.toLowerCase();
    const value = String(nativeGetAttribute.call(element, name) ?? '');
    if (
      lowerCaseName.startsWith('on') ||
      // declarative shadow roots can be closed, which hides their content from these checks
      lowerCaseName === 'shadowrootmode' ||
      lowerCaseName === 'shadowroot' ||
      (lowerCaseName === 'attributename' && /^\s*(on|.*href\s*$)/i.test(value)) ||
      isJavaScriptURL(value)
    ) {
      unsafe.push(name);
    }
  }
  return unsafe;
}

/**
 * Visits `root` and every element below it, including template contents and open shadow roots.
 * Stops at and returns the first element for which `visit` returns true.
 */
function findElement(root: Node, visit: (element: Element) => boolean): Element | undefined {
  const pending: Node[] = [root];
  while (pending.length > 0) {
    const current = pending.pop()!;
    const walker: TreeWalker = nativeCreateTreeWalker.call(document, current, NodeFilter.SHOW_ELEMENT);
    for (let node: Node | null = current; node; node = nativeTreeWalkerNextNode.call(walker)) {
      if (!isElementNode(node)) {
        continue;
      }
      if (visit(node)) {
        return node;
      }
      const shadowRoot = nativeShadowRoot?.call(node);
      if (shadowRoot) {
        pending.push(shadowRoot);
      }
      if (nativeTemplateContent && getElementLocalName(node) === 'template') {
        try {
          const content = nativeTemplateContent.call(node);
          if (content) {
            pending.push(content);
          }
        } catch (e) {
          // not an HTML template element
        }
      }
    }
  }
  return undefined;
}

/**
 * Returns the name of the first element in `node` (or `node` itself) that a plugin must not insert:
 * elements that load a nested document, script elements and <base>.
 */
export function findForbiddenInsertedElement(node: Node): string | undefined {
  const found = findElement(node, (el) => isForbiddenElement(el) || isScriptElement(el) || isBaseElement(el));
  return found ? getElementLocalName(found) : undefined;
}

type SanitizeResult = { forbiddenElement?: string; changed: boolean };

/**
 * Removes from `root` every node that would run script or load a nested document once it is part
 * of the page: frame-like elements, scripts, <base>, <noscript>, event handler attributes,
 * javascript: URLs and declarative shadow roots. `root` itself is kept even if it is unsafe.
 */
export function sanitizeTree(root: Node): SanitizeResult {
  const result: SanitizeResult = { changed: false };
  const removals: Element[] = [];
  findElement(root, (element) => {
    if (isForbiddenElement(element)) {
      result.forbiddenElement ??= getElementLocalName(element);
      removals.push(element);
      return false;
    }
    if (isScriptElement(element) || isBaseElement(element) || getElementLocalName(element) === 'noscript') {
      removals.push(element);
      return false;
    }
    for (const name of getUnsafeAttributeNames(element)) {
      nativeRemoveAttribute.call(element, name);
      result.changed = true;
    }
    return false;
  });
  for (const element of removals) {
    const parent = element === root ? null : nativeParentNode?.call(element);
    if (parent) {
      nativeRemoveChild.call(parent, element);
      result.changed = true;
    }
  }
  return result;
}

function isHTMLDocument(doc: Document | null | undefined): boolean {
  return !!doc && nativeContentType?.call(doc) === 'text/html';
}

export function isInHTMLDocument(node: unknown): boolean {
  if (!isNode(node)) {
    return true;
  }
  return isHTMLDocument(isDocumentNode(node) ? node : nativeOwnerDocument?.call(node));
}

export function getParentNode(node: Node): Node | null {
  return nativeParentNode?.call(node) ?? null;
}

export function getShadowRootHost(root: unknown): Element | null {
  if (getNodeType(root) !== Node.DOCUMENT_FRAGMENT_NODE || !nativeShadowRootHost) {
    return null;
  }
  try {
    return nativeShadowRootHost.call(root);
  } catch (e) {
    // a document fragment that is not a shadow root
    return null;
  }
}

let inertDocument: Document | undefined;

// a document without a browsing context: nothing parsed into it loads, renders or runs
function getInertDocument(): Document {
  if (!inertDocument) {
    inertDocument = document.implementation.createHTMLDocument('');
  }
  return inertDocument;
}

type MarkupParser = { parse: (markup: string) => Node; serialize: (root: Node) => string };

/**
 * Parses markup the same way the browser does for a fragment whose context is `context`
 * (innerHTML, insertAdjacentHTML, ...), but inside an inert document.
 */
export function getFragmentParser(context: Element | null): MarkupParser {
  return {
    parse(markup) {
      const inertDoc = getInertDocument();
      const namespace = context ? getNamespace(context) : XHTML_NAMESPACE;
      const localName = context ? String(nativeLocalName?.call(context)) : 'body';
      const inertContext: Element = nativeCreateElementNS.call(inertDoc, namespace, localName);
      nativeInnerHTMLSetter?.call(inertContext, markup);
      return inertContext;
    },
    serialize(root) {
      return String(nativeInnerHTMLGetter?.call(root) ?? '');
    },
  };
}

export const documentParser: MarkupParser = {
  parse(markup) {
    return nativeParseFromString.call(new DOMParser(), markup, 'text/html');
  },
  serialize(root) {
    const doctype: DocumentType | null = nativeDoctype?.call(root);
    const documentElement: Element | null = nativeDocumentElement?.call(root);
    const serializedDoctype = doctype ? '<!DOCTYPE ' + doctype.name + '>' : '';
    return serializedDoctype + (documentElement ? String(nativeOuterHTMLGetter?.call(documentElement) ?? '') : '');
  },
};

/**
 * Returns markup that is safe to hand to the browser for the given parser context.
 * Throws a ForbiddenElementError if the markup creates an element that loads a nested document.
 *
 * Unsafe nodes are removed from the inert parse and the result is serialized and parsed again,
 * so the returned string is the one that was verified, in the same context it will be parsed in.
 */
export function sanitizeMarkup(markup: string, parser: MarkupParser): string {
  const parsed = parser.parse(markup);
  const firstPass = sanitizeTree(parsed);
  if (firstPass.forbiddenElement) {
    throw new ForbiddenElementError(firstPass.forbiddenElement);
  }
  if (!firstPass.changed) {
    return markup;
  }
  const sanitized = parser.serialize(parsed);
  const secondPass = sanitizeTree(parser.parse(sanitized));
  if (secondPass.forbiddenElement || secondPass.changed) {
    throw new Error('Unsafe HTML is not allowed in sandboxed plugins');
  }
  return sanitized;
}
