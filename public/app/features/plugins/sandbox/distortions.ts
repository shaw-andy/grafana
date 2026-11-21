import { type ProxyTarget } from '@locker/near-membrane-shared';
import DOMPurify from 'dompurify';
import { cloneDeep, isFunction } from 'lodash';

import { type Monaco } from '@grafana/ui';

import { loadScriptIntoSandbox } from './codeLoader';
import { forbiddenElements } from './constants';
import { recursivePatchObjectAsLiveTarget } from './documentSandbox';
import { type SandboxEnvironment, type SandboxPluginMeta } from './types';
import { logWarning, unboxRegexesFromMembraneProxy } from './utils';

/**
 * Distortions are near-membrane mechanisms to altert JS instrics and DOM APIs.
 *
 * Everytime a plugin tries to use a js instricis (e.g. Array.concat) or a DOM API (e.g. document.createElement)
 * or access any of its attributes a distortion callback is used.
 *
 * The distortion callback has a single parameter which is usually the "native" function responsible
 * for the API, but generally speaking is the value that the plugin would normally get. Note that here by
 * "value" we mean the function the plugin would execute, not the value from executing the function.
 *
 * To compare the native code passed to the distortion callback and know if should we distorted or not we need
 * to get the object descriptors of these native functions using Object.getOwnPropertyDescriptors.
 *
 * For example:
 *
 * If the distortionCallback is asking for a distortion for the `Array.concat` function
 * one will see `ƒ concat() { [native code] }` as the parameter to the distortion callback.
 *
 * Inside the callback we could compare this with the descriptor value:
 *
 * ```
 * function distortionCallback(valueToDistort: unknown){
 *   const descriptor = Object.getOwnPropertyDescriptors(Array.prototype, 'concat')
 *   if (descriptor.value === valueToDistort) {
 *      // distorted replacement function
 *      return ArrayConcatReplacementFunction;
 *   }
 *   // original
 *   return valueToDistort;
 * }
 * ```
 *
 * To avoid the verbosity of the previous code as more and more distortions are applied it is easier to use
 * a Map. Map keys can be objects (including native functions).
 *
 * This allows to simplify the previous code:
 *
 * ```
 * function distortionCallback(valueToDistort: unknown){
 *   if (generalDistortionMap.has(valueToDistort)) {
 *      // Map does the comparison easier
 *      return generalDistortionMap.get(valueToDistort);
 *   }
 *   // original
 *   return valueToDistort;
 * }
 * ```
 *
 * The code in this file defines that generalDistortionMap.
 */

type DistortionMap = Map<
  unknown,
  (originalAttrOrMethod: unknown, pluginMeta: SandboxPluginMeta, sandboxEnv?: SandboxEnvironment) => unknown
>;
const generalDistortionMap: DistortionMap = new Map();

const SANDBOX_LIVE_API_PATCHED = Symbol.for('@SANDBOX_LIVE_API_PATCHED');

// A dedicated instance so hooks or config set on the shared DOMPurify instance elsewhere do not apply here.
const sandboxPurify = DOMPurify(window);

export function getGeneralSandboxDistortionMap() {
  if (generalDistortionMap.size === 0) {
    // initialize the distortion map
    distortIframeAttributes(generalDistortionMap);
    distortConsole(generalDistortionMap);
    distortAlert(generalDistortionMap);
    distortAppend(generalDistortionMap);
    distortInsert(generalDistortionMap);
    distortInnerHTML(generalDistortionMap);
    distortParsedDocuments(generalDistortionMap);
    distortAttributes(generalDistortionMap);
    distortScriptURLs(generalDistortionMap);
    distortStringTimers(generalDistortionMap);
    distortCreateElement(generalDistortionMap);
    distortWorkers(generalDistortionMap);
    distortDocument(generalDistortionMap);
    distortMonacoEditor(generalDistortionMap);
    distortPostMessage(generalDistortionMap);
    distortLodash(generalDistortionMap);
  }
  return generalDistortionMap;
}

/*
 * The browser compiles event handler attributes, script elements and javascript: URLs as code of the
 * document that owns them. Nodes created through the APIs plugins reach are owned by the host document,
 * so anything below that lets a plugin put such content into a node would run it outside the sandbox.
 */

const URL_ATTRIBUTES = ['href', 'src', 'action', 'formaction', 'data', 'to', 'from', 'by', 'values'];

function getLocalName(qualifiedName: string): string {
  return qualifiedName.slice(qualifiedName.lastIndexOf(':') + 1).toLowerCase();
}

function isScriptURL(value: string): boolean {
  // the URL parser ignores leading control characters and spaces and tabs or newlines anywhere
  return /^(javascript|vbscript):/i.test(value.replace(/[\u0000-\u0020]/g, ''));
}

function isScriptableAttribute(qualifiedName: string, value: string): boolean {
  const localName = getLocalName(qualifiedName);
  if (localName.startsWith('on')) {
    return true;
  }
  // SVG animations can set another attribute, e.g. <set attributeName="onclick" to="...">
  if (localName === 'attributename' && value.trim().toLowerCase().startsWith('on')) {
    return true;
  }
  return URL_ATTRIBUTES.includes(localName) && isScriptURL(value);
}

function isScriptElement(node: unknown): boolean {
  return node instanceof Element && node.localName.toLowerCase() === 'script';
}

function containsScriptElement(node: unknown): boolean {
  if (isScriptElement(node)) {
    return true;
  }
  return (node instanceof Element || node instanceof DocumentFragment) && node.querySelector('script') !== null;
}

function assertNoScriptElements(nodes: unknown[], meta: SandboxPluginMeta, attrOrMethod: string) {
  for (const node of nodes) {
    if (containsScriptElement(node)) {
      logWarning(`Plugin ${meta.id} tried to insert a script element with ${attrOrMethod}`, {
        pluginId: meta.id,
        attrOrMethod,
        param: 'script',
        entity: 'HTMLElement',
      });
      throw new Error('<script> elements are not allowed in sandboxed plugins');
    }
  }
}

function assertSafeAttribute(qualifiedName: string, value: string, meta: SandboxPluginMeta, attrOrMethod: string) {
  if (isScriptableAttribute(qualifiedName, value)) {
    logWarning(`Plugin ${meta.id} tried to set a forbidden attribute with ${attrOrMethod}`, {
      pluginId: meta.id,
      attrOrMethod,
      param: qualifiedName,
      entity: 'HTMLElement',
    });
    throw new Error(`Setting the attribute "${qualifiedName}" to this value is not allowed in sandboxed plugins`);
  }
}

function assertSafeURL(value: string, meta: SandboxPluginMeta, attrOrMethod: string) {
  if (isScriptURL(value)) {
    logWarning(`Plugin ${meta.id} tried to use a script URL with ${attrOrMethod}`, {
      pluginId: meta.id,
      attrOrMethod,
      entity: 'window',
    });
    throw new Error('javascript: URLs are not allowed in sandboxed plugins');
  }
}

function sanitizeMarkup(
  markup: unknown,
  meta: SandboxPluginMeta,
  attrOrMethod: string,
  purifyConfig: { WHOLE_DOCUMENT?: boolean } = {}
): unknown {
  // innerHTML = null clears the element, keep that behavior
  if (markup === null || markup === undefined) {
    return markup;
  }
  // convert once so an object whose toString changes between calls can't pass different markup to the sink
  const value = String(markup);
  const lowerCase = value.toLowerCase();
  for (const forbiddenElement of forbiddenElements) {
    if (lowerCase.includes('<' + forbiddenElement)) {
      logWarning(`Plugin ${meta.id} tried to set ${forbiddenElement} in ${attrOrMethod}`, {
        pluginId: meta.id,
        attrOrMethod,
        param: forbiddenElement,
        entity: 'HTMLElement',
      });

      throw new Error('<' + forbiddenElement + '> is not allowed in sandboxed plugins');
    }
  }
  // without a tag the parser only creates text
  if (!value.includes('<')) {
    return value;
  }
  const sanitized = sandboxPurify.sanitize(value, purifyConfig);
  if (sandboxPurify.removed.length > 0) {
    logWarning(`Plugin ${meta.id} tried to set forbidden content in ${attrOrMethod}`, {
      pluginId: meta.id,
      attrOrMethod,
      param: value,
      entity: 'HTMLElement',
    });
  }
  return sanitized;
}

/*
 * Removes scriptable content in place from nodes the browser parsed into a document without a browsing
 * context (DOMParser, XMLHttpRequest, XSLT). Nothing in those documents runs until a node is adopted into
 * the host document, so cleaning before the plugin gets the document is enough.
 */
function removeScriptableContent(root: Node) {
  if (!(root instanceof Element || root instanceof Document || root instanceof DocumentFragment)) {
    return;
  }
  const elements: Element[] = Array.from(root.querySelectorAll('*'));
  if (root instanceof Element) {
    elements.unshift(root);
  }
  for (const element of elements) {
    if (isScriptElement(element) || forbiddenElements.includes(element.localName.toLowerCase())) {
      element.remove();
      continue;
    }
    for (const attr of Array.from(element.attributes)) {
      if (isScriptableAttribute(attr.name, attr.value)) {
        element.removeAttributeNode(attr);
      }
    }
    if (element instanceof HTMLTemplateElement) {
      removeScriptableContent(element.content);
    }
    if (element.shadowRoot) {
      removeScriptableContent(element.shadowRoot);
    }
  }
}

function failToSet(originalAttrOrMethod: unknown, meta: SandboxPluginMeta) {
  logWarning(`Plugin ${meta.id} tried to set a sandboxed property`, {
    pluginId: meta.id,
    attrOrMethod: String(originalAttrOrMethod),
    entity: 'window',
  });
  return () => {
    throw new Error('Plugins are not allowed to set sandboxed properties');
  };
}

// sets distortion to protect iframe elements
function distortIframeAttributes(distortions: DistortionMap) {
  const iframeHtmlForbiddenProperties = ['contentDocument', 'contentWindow', 'src', 'srcdoc', 'srcObject', 'srcset'];

  for (const property of iframeHtmlForbiddenProperties) {
    const descriptor = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, property);
    if (descriptor) {
      function fail(originalAttrOrMethod: unknown, meta: SandboxPluginMeta) {
        const pluginId = meta.id;
        logWarning(`Plugin ${pluginId} tried to access iframe.${property}`, {
          pluginId,
          attrOrMethod: property,
          entity: 'iframe',
        });

        return () => {
          throw new Error('iframe.' + property + ' is not allowed in sandboxed plugins');
        };
      }

      if (descriptor.value) {
        distortions.set(descriptor.value, fail);
      }
      if (descriptor.set) {
        distortions.set(descriptor.set, fail);
      }
      if (descriptor.get) {
        distortions.set(descriptor.get, fail);
      }
    }
  }
}

// set distortions to always prefix any usage of console
function distortConsole(distortions: DistortionMap) {
  const descriptor = Object.getOwnPropertyDescriptor(window, 'console');
  if (descriptor?.value) {
    function getSandboxConsole(originalAttrOrMethod: unknown, meta: SandboxPluginMeta) {
      const pluginId = meta.id;

      function sandboxLog(...args: unknown[]) {
        console.log(`[plugin ${pluginId}]`, ...args);
      }
      return {
        log: sandboxLog,
        warn: sandboxLog,
        error: sandboxLog,
        info: sandboxLog,
        debug: sandboxLog,
        table: sandboxLog,
      };
    }

    distortions.set(descriptor.value, getSandboxConsole);
  }
  if (descriptor?.set) {
    distortions.set(descriptor.set, failToSet);
  }
}

// set distortions to alert to always output to the console
function distortAlert(distortions: DistortionMap) {
  function getAlertDistortion(originalAttrOrMethod: unknown, meta: SandboxPluginMeta) {
    const pluginId = meta.id;
    logWarning(`Plugin ${pluginId} accessed window.alert`, {
      pluginId,
      attrOrMethod: 'alert',
      entity: 'window',
    });

    return function (...args: unknown[]) {
      console.log(`[plugin ${pluginId}]`, ...args);
    };
  }
  const descriptor = Object.getOwnPropertyDescriptor(window, 'alert');
  if (descriptor?.value) {
    distortions.set(descriptor.value, getAlertDistortion);
  }
  if (descriptor?.set) {
    distortions.set(descriptor.set, failToSet);
  }
}

// sets distortions to sanitize every API that parses plugin markup into nodes of the host document
function distortInnerHTML(distortions: DistortionMap) {
  function getMarkupDistortion(
    markupArgIndex: number,
    attrOrMethod: string,
    purifyConfig?: { WHOLE_DOCUMENT?: boolean }
  ) {
    return function (originalMethod: unknown, meta: SandboxPluginMeta) {
      return function markupDistortion(this: unknown, ...args: unknown[]) {
        if (args.length > markupArgIndex) {
          args[markupArgIndex] = sanitizeMarkup(args[markupArgIndex], meta, attrOrMethod, purifyConfig);
        }
        if (isFunction(originalMethod)) {
          return originalMethod.apply(this, args);
        }
      };
    };
  }

  const sinks: Array<{
    target: object | undefined;
    property: string;
    markupArgIndex: number;
    purifyConfig?: { WHOLE_DOCUMENT?: boolean };
  }> = [
    { target: Element.prototype, property: 'innerHTML', markupArgIndex: 0 },
    { target: Element.prototype, property: 'outerHTML', markupArgIndex: 0 },
    { target: Element.prototype, property: 'insertAdjacentHTML', markupArgIndex: 1 },
    { target: Element.prototype, property: 'setHTMLUnsafe', markupArgIndex: 0 },
    { target: ShadowRoot.prototype, property: 'innerHTML', markupArgIndex: 0 },
    { target: ShadowRoot.prototype, property: 'setHTMLUnsafe', markupArgIndex: 0 },
    { target: Range.prototype, property: 'createContextualFragment', markupArgIndex: 0 },
    { target: Document, property: 'parseHTMLUnsafe', markupArgIndex: 0, purifyConfig: { WHOLE_DOCUMENT: true } },
  ];

  for (const { target, property, markupArgIndex, purifyConfig } of sinks) {
    const descriptor = target && Object.getOwnPropertyDescriptor(target, property);
    const distortion = getMarkupDistortion(markupArgIndex, property, purifyConfig);
    if (descriptor?.set) {
      distortions.set(descriptor.set, distortion);
    }
    if (descriptor?.value) {
      distortions.set(descriptor.value, distortion);
    }
  }

  function getExecCommandDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    return function execCommandDistortion(this: Document, ...args: unknown[]) {
      const command = String(args[0]).toLowerCase();
      if (args.length > 2 && command === 'inserthtml') {
        args[2] = sanitizeMarkup(args[2], meta, 'execCommand');
      }
      if (args.length > 2 && (command === 'createlink' || command === 'insertimage')) {
        const url = String(args[2]);
        assertSafeURL(url, meta, 'execCommand');
        args[2] = url;
      }
      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, args);
      }
    };
  }
  const execCommandDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'execCommand');
  if (execCommandDescriptor?.value) {
    distortions.set(execCommandDescriptor.value, getExecCommandDistortion);
  }
}

// sets distortions to clean documents the browser parses outside the host document before plugins get them
function distortParsedDocuments(distortions: DistortionMap) {
  function getParseDistortion(originalMethod: unknown) {
    return function parseDistortion(this: unknown, ...args: unknown[]) {
      if (!isFunction(originalMethod)) {
        return undefined;
      }
      const result = originalMethod.apply(this, args);
      if (result instanceof Node) {
        removeScriptableContent(result);
      }
      return result;
    };
  }

  const cleanedDocuments = new WeakSet<Document>();
  function getResponseDocumentDistortion(originalGetter: unknown) {
    return function responseDocumentDistortion(this: XMLHttpRequest) {
      if (!isFunction(originalGetter)) {
        return undefined;
      }
      const result = originalGetter.call(this);
      if (result instanceof Document && !cleanedDocuments.has(result)) {
        removeScriptableContent(result);
        cleanedDocuments.add(result);
      }
      return result;
    };
  }

  const parseDescriptors = [Object.getOwnPropertyDescriptor(DOMParser.prototype, 'parseFromString')];
  if (typeof XSLTProcessor !== 'undefined') {
    parseDescriptors.push(
      Object.getOwnPropertyDescriptor(XSLTProcessor.prototype, 'transformToFragment'),
      Object.getOwnPropertyDescriptor(XSLTProcessor.prototype, 'transformToDocument')
    );
  }
  for (const descriptor of parseDescriptors) {
    if (descriptor?.value) {
      distortions.set(descriptor.value, getParseDistortion);
    }
  }

  for (const property of ['responseXML', 'response']) {
    const descriptor = Object.getOwnPropertyDescriptor(XMLHttpRequest.prototype, property);
    if (descriptor?.get) {
      distortions.set(descriptor.get, getResponseDocumentDistortion);
    }
  }
}

// sets distortions to prevent plugins from setting event handler attributes or script URLs as attributes
function distortAttributes(distortions: DistortionMap) {
  function getSetAttributeDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    return function setAttributeDistortion(this: Element, ...args: unknown[]) {
      if (args.length >= 2) {
        const name = String(args[0]);
        const value = String(args[1]);
        assertSafeAttribute(name, value, meta, 'setAttribute');
        args[0] = name;
        args[1] = value;
      }
      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, args);
      }
    };
  }

  function getSetAttributeNSDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    return function setAttributeNSDistortion(this: Element, ...args: unknown[]) {
      if (args.length >= 3) {
        const qualifiedName = String(args[1]);
        const value = String(args[2]);
        assertSafeAttribute(qualifiedName, value, meta, 'setAttributeNS');
        args[1] = qualifiedName;
        args[2] = value;
      }
      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, args);
      }
    };
  }

  function getSetAttributeNodeDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    return function setAttributeNodeDistortion(this: Element | NamedNodeMap, attr?: unknown) {
      if (attr instanceof Attr) {
        assertSafeAttribute(attr.name, attr.value, meta, 'setAttributeNode');
      }
      if (isFunction(originalMethod)) {
        return originalMethod.call(this, attr);
      }
    };
  }

  // changes the value of an Attr node, which can already belong to an element
  function getAttrValueDistortion(originalSetter: unknown, meta: SandboxPluginMeta) {
    return function attrValueDistortion(this: Node, value: unknown) {
      if (this instanceof Attr) {
        const attrValue = value === null ? '' : String(value);
        assertSafeAttribute(this.name, attrValue, meta, 'Attr.value');
        value = attrValue;
      }
      if (isFunction(originalSetter)) {
        return originalSetter.call(this, value);
      }
    };
  }

  const setAttributeDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'setAttribute');
  if (setAttributeDescriptor?.value) {
    distortions.set(setAttributeDescriptor.value, getSetAttributeDistortion);
  }

  const setAttributeNSDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'setAttributeNS');
  if (setAttributeNSDescriptor?.value) {
    distortions.set(setAttributeNSDescriptor.value, getSetAttributeNSDistortion);
  }

  const attributeNodeDescriptors = [
    Object.getOwnPropertyDescriptor(Element.prototype, 'setAttributeNode'),
    Object.getOwnPropertyDescriptor(Element.prototype, 'setAttributeNodeNS'),
    Object.getOwnPropertyDescriptor(NamedNodeMap.prototype, 'setNamedItem'),
    Object.getOwnPropertyDescriptor(NamedNodeMap.prototype, 'setNamedItemNS'),
  ];
  for (const descriptor of attributeNodeDescriptors) {
    if (descriptor?.value) {
      distortions.set(descriptor.value, getSetAttributeNodeDistortion);
    }
  }

  const attrValueDescriptors = [
    Object.getOwnPropertyDescriptor(Attr.prototype, 'value'),
    Object.getOwnPropertyDescriptor(Node.prototype, 'nodeValue'),
    Object.getOwnPropertyDescriptor(Node.prototype, 'textContent'),
  ];
  for (const descriptor of attrValueDescriptors) {
    if (descriptor?.set) {
      distortions.set(descriptor.set, getAttrValueDistortion);
    }
  }
}

// sets distortions to prevent plugins from navigating to javascript: URLs, which run in the host page
function distortScriptURLs(distortions: DistortionMap) {
  function getURLSetterDistortion(originalSetter: unknown, meta: SandboxPluginMeta) {
    return function urlSetterDistortion(this: unknown, value: unknown) {
      const url = String(value);
      assertSafeURL(url, meta, 'url setter');
      if (isFunction(originalSetter)) {
        return originalSetter.call(this, url);
      }
    };
  }

  function getURLMethodDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    return function urlMethodDistortion(this: unknown, ...args: unknown[]) {
      if (args.length > 0 && args[0] !== undefined) {
        const url = String(args[0]);
        assertSafeURL(url, meta, 'navigation');
        args[0] = url;
      }
      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, args);
      }
    };
  }

  // document.open(url, name, features) opens a window like window.open
  function getDocumentOpenDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    return function documentOpenDistortion(this: Document, ...args: unknown[]) {
      if (args.length >= 3) {
        const url = String(args[0]);
        assertSafeURL(url, meta, 'document.open');
        args[0] = url;
      }
      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, args);
      }
    };
  }

  const urlSetters: Array<[object | undefined, string]> = [
    [HTMLAnchorElement.prototype, 'href'],
    [HTMLAnchorElement.prototype, 'protocol'],
    [HTMLAreaElement.prototype, 'href'],
    [HTMLAreaElement.prototype, 'protocol'],
    [HTMLBaseElement.prototype, 'href'],
    [HTMLFormElement.prototype, 'action'],
    [HTMLButtonElement.prototype, 'formAction'],
    [HTMLInputElement.prototype, 'formAction'],
    [HTMLObjectElement.prototype, 'data'],
    [HTMLEmbedElement.prototype, 'src'],
    [typeof HTMLFrameElement !== 'undefined' ? HTMLFrameElement.prototype : undefined, 'src'],
    [SVGAnimatedString.prototype, 'baseVal'],
    // Location and document.location are unforgeable, their accessors live on the instances
    [window.location, 'href'],
    [Location.prototype, 'href'],
    [document, 'location'],
    [Document.prototype, 'location'],
  ];
  for (const [target, property] of urlSetters) {
    const descriptor = target && Object.getOwnPropertyDescriptor(target, property);
    if (descriptor?.set) {
      distortions.set(descriptor.set, getURLSetterDistortion);
    }
  }

  const urlMethods: Array<[object | undefined, string]> = [
    [window.location, 'assign'],
    [window.location, 'replace'],
    [Location.prototype, 'assign'],
    [Location.prototype, 'replace'],
    [window, 'open'],
    [Window.prototype, 'open'],
    [typeof Navigation !== 'undefined' ? Navigation.prototype : undefined, 'navigate'],
  ];
  for (const [target, property] of urlMethods) {
    const descriptor = target && Object.getOwnPropertyDescriptor(target, property);
    if (descriptor?.value) {
      distortions.set(descriptor.value, getURLMethodDistortion);
    }
  }

  const documentOpenDescriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'open');
  if (documentOpenDescriptor?.value) {
    distortions.set(documentOpenDescriptor.value, getDocumentOpenDistortion);
  }
}

// setTimeout and setInterval evaluate a string handler in the host page, evaluate it in the sandbox instead
function distortStringTimers(distortions: DistortionMap) {
  function getTimerDistortion(originalMethod: unknown, meta: SandboxPluginMeta, sandboxEnv?: SandboxEnvironment) {
    return function timerDistortion(this: unknown, ...args: unknown[]) {
      if (args.length > 0 && typeof args[0] !== 'function') {
        const code = String(args[0]);
        logWarning(`Plugin ${meta.id} used a string handler in a timer`, {
          pluginId: meta.id,
          attrOrMethod: 'setTimeout',
          entity: 'window',
        });
        if (!sandboxEnv) {
          throw new Error('String handlers in timers are not allowed in sandboxed plugins');
        }
        args[0] = () => sandboxEnv.evaluate(code);
      }
      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, args);
      }
    };
  }

  for (const timer of ['setTimeout', 'setInterval']) {
    const descriptor = Object.getOwnPropertyDescriptor(window, timer);
    if (descriptor?.value) {
      distortions.set(descriptor.value, getTimerDistortion);
    }
  }
}

function distortCreateElement(distortions: DistortionMap) {
  function getCreateElementDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    const pluginId = meta.id;
    return function createElementDistortion(this: HTMLElement, arg?: string, options?: unknown) {
      if (arg && forbiddenElements.includes(arg)) {
        logWarning(`Plugin ${pluginId} tried to create ${arg}`, {
          pluginId,
          attrOrMethod: 'createElement',
          param: arg,
          entity: 'document',
        });
        return document.createDocumentFragment();
      }
      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, [arg, options]);
      }
    };
  }
  const descriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'createElement');
  if (descriptor?.value) {
    distortions.set(descriptor.value, getCreateElementDistortion);
  }
}

function isForbiddenNode(node: unknown): node is Node {
  return node instanceof Node && forbiddenElements.includes(node.nodeName.toLowerCase());
}

function distortInsert(distortions: DistortionMap) {
  // methods that insert the single node passed at nodeArgIndex
  function getInsertDistortion(nodeArgIndex: number, attrOrMethod: string) {
    return function (originalMethod: unknown, meta: SandboxPluginMeta) {
      const pluginId = meta.id;
      return function insertDistortion(this: unknown, ...args: unknown[]) {
        const node = args[nodeArgIndex];
        if (isForbiddenNode(node)) {
          const nodeType = node.nodeName.toLowerCase();
          logWarning(`Plugin ${pluginId} tried to insert ${nodeType}`, {
            pluginId,
            attrOrMethod,
            param: nodeType,
            entity: 'HTMLElement',
          });
          return document.createDocumentFragment();
        }
        assertNoScriptElements([node], meta, attrOrMethod);
        if (isFunction(originalMethod)) {
          return originalMethod.apply(this, args);
        }
      };
    };
  }

  const singleNodeMethods: Array<[object, string, number]> = [
    [Node.prototype, 'insertBefore', 0],
    [Node.prototype, 'replaceChild', 0],
    [Element.prototype, 'insertAdjacentElement', 1],
    [Range.prototype, 'insertNode', 0],
    [Range.prototype, 'surroundContents', 0],
  ];

  for (const [target, property, nodeArgIndex] of singleNodeMethods) {
    const descriptor = Object.getOwnPropertyDescriptor(target, property);
    if (descriptor?.value) {
      distortions.set(descriptor.value, getInsertDistortion(nodeArgIndex, property));
    }
  }
}

// set distortions to append elements to the document
function distortAppend(distortions: DistortionMap) {
  // append accepts an array of nodes to append https://developer.mozilla.org/en-US/docs/Web/API/Node/append
  function getAppendDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    const pluginId = meta.id;
    return function appendDistortion(this: HTMLElement, ...args: unknown[]) {
      const acceptedNodes = args.filter((node) => !isForbiddenNode(node));

      if (acceptedNodes.length !== args.length) {
        logWarning(`Plugin ${pluginId} tried to append fobiddenElements`, {
          pluginId,
          attrOrMethod: 'append',
          param:
            args
              .filter(isForbiddenNode)
              .map((node) => node.nodeName.toLowerCase())
              .join(',') || '',
          entity: 'HTMLElement',
        });
      }

      assertNoScriptElements(acceptedNodes, meta, 'append');

      if (isFunction(originalMethod)) {
        originalMethod.apply(this, acceptedNodes);
      }
      // https://developer.mozilla.org/en-US/docs/Web/API/Element/append#return_value
      return undefined;
    };
  }

  // appendChild accepts a single node to add https://developer.mozilla.org/en-US/docs/Web/API/Node/appendChild
  function getAppendChildDistortion(originalMethod: unknown, meta: SandboxPluginMeta, sandboxEnv?: SandboxEnvironment) {
    const pluginId = meta.id;
    return function appendChildDistortion(this: HTMLElement, arg?: Node) {
      const nodeType = arg?.nodeName?.toLowerCase() || '';
      if (arg && forbiddenElements.includes(nodeType)) {
        logWarning(`Plugin ${pluginId} tried to append ${nodeType}`, {
          pluginId,
          attrOrMethod: 'appendChild',
          param: nodeType,
          entity: 'HTMLElement',
        });

        return document.createDocumentFragment();
      }
      // if the node is a script, load it into the sandbox
      // this allows webpack chunks to be loaded into the sandbox
      // loadScriptIntoSandbox has restrictions on what scripts can be loaded
      if (sandboxEnv && arg && nodeType === 'script' && arg instanceof HTMLScriptElement) {
        loadScriptIntoSandbox(arg.src, sandboxEnv)
          .then(() => {
            arg.onload?.call(arg, new Event('load'));
          })
          .catch((err) => {
            arg.onerror?.call(arg, new ErrorEvent('error', { error: err }));
          });
        return undefined;
      }
      assertNoScriptElements([arg], meta, 'appendChild');
      if (isFunction(originalMethod)) {
        return originalMethod.call(this, arg);
      }
    };
  }

  const descriptors = [
    Object.getOwnPropertyDescriptor(Element.prototype, 'append'),
    Object.getOwnPropertyDescriptor(Element.prototype, 'prepend'),
    Object.getOwnPropertyDescriptor(Element.prototype, 'after'),
    Object.getOwnPropertyDescriptor(Element.prototype, 'before'),
    Object.getOwnPropertyDescriptor(Element.prototype, 'replaceWith'),
    Object.getOwnPropertyDescriptor(Element.prototype, 'replaceChildren'),
    Object.getOwnPropertyDescriptor(Document.prototype, 'append'),
    Object.getOwnPropertyDescriptor(Document.prototype, 'prepend'),
    Object.getOwnPropertyDescriptor(Document.prototype, 'replaceChildren'),
    Object.getOwnPropertyDescriptor(DocumentFragment.prototype, 'append'),
    Object.getOwnPropertyDescriptor(DocumentFragment.prototype, 'prepend'),
    Object.getOwnPropertyDescriptor(DocumentFragment.prototype, 'replaceChildren'),
    Object.getOwnPropertyDescriptor(CharacterData.prototype, 'after'),
    Object.getOwnPropertyDescriptor(CharacterData.prototype, 'before'),
    Object.getOwnPropertyDescriptor(CharacterData.prototype, 'replaceWith'),
    Object.getOwnPropertyDescriptor(DocumentType.prototype, 'after'),
    Object.getOwnPropertyDescriptor(DocumentType.prototype, 'before'),
    Object.getOwnPropertyDescriptor(DocumentType.prototype, 'replaceWith'),
  ];

  for (const descriptor of descriptors) {
    if (descriptor?.value) {
      distortions.set(descriptor.value, getAppendDistortion);
    }
  }

  const appendChildDescriptor = Object.getOwnPropertyDescriptor(Node.prototype, 'appendChild');
  if (appendChildDescriptor?.value) {
    distortions.set(appendChildDescriptor.value, getAppendChildDistortion);
  }
}

// this is not a distortion for security reasons but to make plugins using web workers work correctly.
function distortWorkers(distortions: DistortionMap) {
  const descriptor = Object.getOwnPropertyDescriptor(Worker.prototype, 'postMessage');
  function getPostMessageDistortion(originalMethod: unknown) {
    return function postMessageDistortion(this: Worker, ...args: unknown[]) {
      // proxies can't be serialized by postMessage algorithm
      // the only way to pass it through is to send a cloned version
      // objects passed to postMessage should be clonable
      try {
        const newArgs: unknown[] = cloneDeep(args);
        if (isFunction(originalMethod)) {
          originalMethod.apply(this, newArgs);
        }
      } catch (e) {
        throw new Error('postMessage arguments are invalid objects');
      }
    };
  }
  if (descriptor?.value) {
    distortions.set(descriptor.value, getPostMessageDistortion);
  }
}

// this is not a distortion for security reasons but to make plugins using document.defaultView work correctly.
function distortDocument(distortions: DistortionMap) {
  const descriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'defaultView');
  if (descriptor?.get) {
    distortions.set(descriptor.get, () => {
      return () => {
        return window;
      };
    });
  }

  const documentForbiddenMethods = ['write', 'writeln'];
  for (const method of documentForbiddenMethods) {
    const descriptor = Object.getOwnPropertyDescriptor(Document.prototype, method);
    if (descriptor?.set) {
      distortions.set(descriptor.set, failToSet);
    }
    if (descriptor?.value) {
      distortions.set(descriptor.value, failToSet);
    }
  }
}

async function distortMonacoEditor(distortions: DistortionMap) {
  // We rely on `monaco` being instanciated inside `window.monaco`.
  // this is the same object passed down to plugins using monaco editor for their editors
  // this `window.monaco` is an instance of monaco but not the same as if we
  // import `monaco-editor` directly in this file.
  // Short of abusing the `window.monaco` object we would have to modify grafana-ui to export
  // the monaco instance directly in the ReactMonacoEditor component
  const monacoEditor: Monaco = Reflect.get(window, 'monaco');

  // do not double patch
  if (!monacoEditor || Object.hasOwn(monacoEditor, SANDBOX_LIVE_API_PATCHED)) {
    return;
  }
  const originalSetMonarchTokensProvider = monacoEditor.languages.setMonarchTokensProvider;

  // NOTE: this function in particular is called only once per intialized custom language inside a plugin which is a
  // rare ocurrance but if not patched it'll break the syntax highlighting for the custom language.
  function getSetMonarchTokensProvider() {
    return function (...args: Parameters<typeof originalSetMonarchTokensProvider>) {
      if (args.length !== 2) {
        return originalSetMonarchTokensProvider.apply(monacoEditor, args);
      }
      return originalSetMonarchTokensProvider.call(
        monacoEditor,
        args[0],
        unboxRegexesFromMembraneProxy(args[1]) as (typeof args)[1]
      );
    };
  }
  distortions.set(monacoEditor.languages.setMonarchTokensProvider, getSetMonarchTokensProvider);
  Reflect.set(monacoEditor, SANDBOX_LIVE_API_PATCHED, {});
}

async function distortPostMessage(distortions: DistortionMap) {
  const descriptor = Object.getOwnPropertyDescriptor(window, 'postMessage');

  function getPostMessageDistortion(originalMethod: unknown) {
    return function postMessageDistortion(this: Window, ...args: unknown[]) {
      // proxies can't be serialized by postMessage algorithm
      // the only way to pass it through is to send a cloned version
      // objects passed to postMessage should be clonable
      try {
        const newArgs: unknown[] = cloneDeep(args);
        if (isFunction(originalMethod)) {
          originalMethod.apply(this, newArgs);
        }
      } catch (e) {
        throw new Error('postMessage arguments are invalid objects');
      }
    };
  }

  if (descriptor?.value) {
    distortions.set(descriptor.value, getPostMessageDistortion);
  }
}

/**
 * "Live" APIs are APIs that can only be distorted at runtime.
 * This could be because the objects we want to patch only become available after specific states are reached,
 * or because the libraries we want to patch are lazy-loaded and we don't have access to their definitions.
 * We put here only distortions that can't be static because they are dynamicly loaded
 */
export function distortLiveApis(_originalValue: ProxyTarget): ProxyTarget | undefined {
  distortMonacoEditor(generalDistortionMap);
  return;
}

function distortLodash(distortions: DistortionMap) {
  /**
   * This is a distortion for lodash clone Deep function
   * because lodash deep clones execute in the blue realm
   * it returns objects that plugins can't modify because they are not
   * lived tracked.
   *
   * We need to patch it so that plugins can modify the cloned object
   * in places such as query editors.
   *
   */
  function cloneDeepDistortion(originalValue: unknown) {
    // here to please typescript, this if is never true
    if (!isFunction(originalValue)) {
      return originalValue;
    }
    return function (this: unknown, ...args: unknown[]) {
      const cloned = originalValue.apply(this, args);
      recursivePatchObjectAsLiveTarget(cloned);
      return cloned;
    };
  }
  distortions.set(cloneDeep, cloneDeepDistortion);
}
