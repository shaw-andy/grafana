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

export function getGeneralSandboxDistortionMap() {
  if (generalDistortionMap.size === 0) {
    // initialize the distortion map
    distortIframeAttributes(generalDistortionMap);
    distortConsole(generalDistortionMap);
    distortAlert(generalDistortionMap);
    distortAppend(generalDistortionMap);
    distortInsert(generalDistortionMap);
    distortHTMLSinks(generalDistortionMap);
    distortSetAttribute(generalDistortionMap);
    distortCreateElement(generalDistortionMap);
    distortWorkers(generalDistortionMap);
    distortDocument(generalDistortionMap);
    distortMonacoEditor(generalDistortionMap);
    distortPostMessage(generalDistortionMap);
    distortLodash(generalDistortionMap);
  }
  return generalDistortionMap;
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

// Any markup a sandboxed plugin writes into the real document must be sanitized,
// otherwise the browser executes inline scripts and event-handler attributes in
// the host page, outside the membrane. DOMPurify strips <script>, <iframe>,
// `on*` handlers and `javascript:` URLs while keeping benign markup intact.
// NOTE: DOMPurify's anti-tamper mechanism requires the value to be passed in
// untouched. Calling any method on a membrane proxy string tampers with it and
// makes DOMPurify return an empty string, so the raw argument is handed over
// directly instead of being normalized first.
function sanitizeHTMLArgument(value: unknown): unknown {
  if (typeof value !== 'string') {
    return value;
  }
  return DOMPurify.sanitize(value);
}

function isHTMLMimeType(type: unknown): boolean {
  if (type === undefined || type === null) {
    return true;
  }
  return String(type).toLowerCase().includes('html');
}

// Distorts every sink that parses a string as HTML and attaches it to the real
// document. Each sink receives the markup on a different argument, so the index
// is passed in explicitly.
function distortHTMLSinks(distortions: DistortionMap) {
  function getHTMLSinkDistortion(htmlArgIndex: number, guardByMimeType = false) {
    return function htmlSinkDistortionFactory(originalMethod: unknown, meta: SandboxPluginMeta) {
      const pluginId = meta.id;
      return function htmlSinkDistortion(this: unknown, ...args: unknown[]) {
        if (args.length > htmlArgIndex && (!guardByMimeType || isHTMLMimeType(args[htmlArgIndex + 1]))) {
          const sanitized = sanitizeHTMLArgument(args[htmlArgIndex]);
          if (sanitized !== args[htmlArgIndex]) {
            logWarning(`Plugin ${pluginId} wrote markup into the host page that was sanitized`, {
              pluginId,
              attrOrMethod: 'htmlSink',
              entity: 'HTMLElement',
            });
          }
          args[htmlArgIndex] = sanitized;
        }
        if (isFunction(originalMethod)) {
          return originalMethod.apply(this, args);
        }
      };
    };
  }

  const setterSinks: Array<[PropertyDescriptor | undefined, number]> = [
    [Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML'), 0],
    [Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML'), 0],
  ];
  if (typeof ShadowRoot !== 'undefined') {
    setterSinks.push([Object.getOwnPropertyDescriptor(ShadowRoot.prototype, 'innerHTML'), 0]);
  }
  for (const [descriptor, htmlArgIndex] of setterSinks) {
    if (descriptor?.set) {
      distortions.set(descriptor.set, getHTMLSinkDistortion(htmlArgIndex));
    }
  }

  const methodSinks: Array<[PropertyDescriptor | undefined, number, boolean]> = [
    [Object.getOwnPropertyDescriptor(Element.prototype, 'insertAdjacentHTML'), 1, false],
    [Object.getOwnPropertyDescriptor(Element.prototype, 'setHTMLUnsafe'), 0, false],
    [Object.getOwnPropertyDescriptor(Range.prototype, 'createContextualFragment'), 0, false],
    [Object.getOwnPropertyDescriptor(DOMParser.prototype, 'parseFromString'), 0, true],
  ];
  if (typeof ShadowRoot !== 'undefined') {
    methodSinks.push([Object.getOwnPropertyDescriptor(ShadowRoot.prototype, 'setHTMLUnsafe'), 0, false]);
  }
  // Document.parseHTMLUnsafe is a static method, so its descriptor lives on the
  // Document constructor rather than the prototype.
  methodSinks.push([Object.getOwnPropertyDescriptor(Document, 'parseHTMLUnsafe'), 0, false]);

  for (const [descriptor, htmlArgIndex, guardByMimeType] of methodSinks) {
    if (descriptor?.value) {
      distortions.set(descriptor.value, getHTMLSinkDistortion(htmlArgIndex, guardByMimeType));
    }
  }

  // document.execCommand('insertHTML', showUI, markup) parses its third argument
  // as HTML in the host document, so it needs the same sanitization.
  function getExecCommandDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    const pluginId = meta.id;
    return function execCommandDistortion(this: Document, ...args: unknown[]) {
      const command = String(args[0] ?? '').toLowerCase();
      if (command === 'inserthtml' && args.length > 2) {
        const sanitized = sanitizeHTMLArgument(args[2]);
        if (sanitized !== args[2]) {
          logWarning(`Plugin ${pluginId} wrote markup into the host page that was sanitized`, {
            pluginId,
            attrOrMethod: 'execCommand',
            entity: 'document',
          });
        }
        args[2] = sanitized;
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

function isForbiddenAttribute(name: unknown, value: unknown): boolean {
  const attributeName = String(name ?? '').toLowerCase();
  // Event-handler attributes (onerror, onload, onpointerenter, ...) run script
  // in the host page as soon as the element is attached.
  if (attributeName.startsWith('on')) {
    return true;
  }
  // Strip whitespace and control characters so obfuscated URLs such as
  // "java\tscript:" are still recognized.
  const attributeValue = String(value ?? '')
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u0020]+/g, '')
    .toLowerCase();
  return attributeValue.startsWith('javascript:') || attributeValue.startsWith('vbscript:');
}

// setAttribute and its variants are not covered by property distortions, so a
// plugin could otherwise install an `onerror` handler or a `javascript:` URL on
// a real host element and have the browser execute it outside the membrane.
function distortSetAttribute(distortions: DistortionMap) {
  function reject(meta: SandboxPluginMeta, attrOrMethod: string, name: unknown) {
    logWarning(`Plugin ${meta.id} tried to set a forbidden attribute`, {
      pluginId: meta.id,
      attrOrMethod,
      param: String(name ?? ''),
      entity: 'HTMLElement',
    });
  }

  function getSetAttributeDistortion(nameIndex: number, valueIndex: number) {
    return function setAttributeDistortionFactory(originalMethod: unknown, meta: SandboxPluginMeta) {
      return function setAttributeDistortion(this: Element, ...args: unknown[]) {
        if (isForbiddenAttribute(args[nameIndex], args[valueIndex])) {
          reject(meta, 'setAttribute', args[nameIndex]);
          return undefined;
        }
        if (isFunction(originalMethod)) {
          return originalMethod.apply(this, args);
        }
        return undefined;
      };
    };
  }

  function getSetAttributeNodeDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    return function setAttributeNodeDistortion(this: unknown, attr?: Attr) {
      if (attr && isForbiddenAttribute(attr.name, attr.value)) {
        reject(meta, 'setAttributeNode', attr.name);
        return undefined;
      }
      if (isFunction(originalMethod)) {
        return originalMethod.call(this, attr);
      }
      return undefined;
    };
  }

  const byNameValue: Array<[string, number, number]> = [
    // setAttribute(name, value)
    ['setAttribute', 0, 1],
    // setAttributeNS(namespace, name, value)
    ['setAttributeNS', 1, 2],
  ];
  for (const [method, nameIndex, valueIndex] of byNameValue) {
    const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, method);
    if (descriptor?.value) {
      distortions.set(descriptor.value, getSetAttributeDistortion(nameIndex, valueIndex));
    }
  }

  for (const method of ['setAttributeNode', 'setAttributeNodeNS']) {
    const descriptor = Object.getOwnPropertyDescriptor(Element.prototype, method);
    if (descriptor?.value) {
      distortions.set(descriptor.value, getSetAttributeNodeDistortion);
    }
  }

  // element.attributes.setNamedItem(attr) is another way to install an attribute
  // node, bypassing setAttributeNode.
  if (typeof NamedNodeMap !== 'undefined') {
    for (const method of ['setNamedItem', 'setNamedItemNS']) {
      const descriptor = Object.getOwnPropertyDescriptor(NamedNodeMap.prototype, method);
      if (descriptor?.value) {
        distortions.set(descriptor.value, getSetAttributeNodeDistortion);
      }
    }
  }
}

function distortCreateElement(distortions: DistortionMap) {
  function getCreateElementDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    const pluginId = meta.id;
    return function createElementDistortion(this: HTMLElement, arg?: string, options?: unknown) {
      if (arg && forbiddenElements.includes(String(arg).toLowerCase())) {
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
  // createElementNS lets a plugin create the same forbidden elements (e.g. an
  // iframe in the XHTML namespace) while bypassing the createElement check.
  function getCreateElementNSDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    const pluginId = meta.id;
    return function createElementNSDistortion(this: HTMLElement, ...args: unknown[]) {
      const qualifiedName = args[1];
      if (qualifiedName && forbiddenElements.includes(String(qualifiedName).toLowerCase())) {
        logWarning(`Plugin ${pluginId} tried to create ${String(qualifiedName)}`, {
          pluginId,
          attrOrMethod: 'createElementNS',
          param: String(qualifiedName),
          entity: 'document',
        });
        return document.createDocumentFragment();
      }
      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, args);
      }
    };
  }
  const descriptor = Object.getOwnPropertyDescriptor(Document.prototype, 'createElement');
  if (descriptor?.value) {
    distortions.set(descriptor.value, getCreateElementDistortion);
  }
  const descriptorNS = Object.getOwnPropertyDescriptor(Document.prototype, 'createElementNS');
  if (descriptorNS?.value) {
    distortions.set(descriptorNS.value, getCreateElementNSDistortion);
  }
}

// A plugin loads webpack chunks by attaching <script> elements to the document.
// We never let those run in the host page: a same-domain/CDN src is re-fetched
// and evaluated inside the sandbox instead, and anything else (e.g. an inline
// script) is dropped. This mirrors the <script> handling in appendChild so that
// every insertion API neutralizes scripts the same way.
function routeScriptNodeThroughSandbox(node: Node, sandboxEnv?: SandboxEnvironment): void {
  if (sandboxEnv && node instanceof HTMLScriptElement) {
    loadScriptIntoSandbox(node.src, sandboxEnv)
      .then(() => {
        node.onload?.call(node, new Event('load'));
      })
      .catch((err) => {
        node.onerror?.call(node, new ErrorEvent('error', { error: err }));
      });
  }
}

// Returns true when the node must not be inserted into the host document as-is
// (forbidden elements are dropped, scripts are routed through the sandbox).
function shouldBlockHostInsertion(node: Node, meta: SandboxPluginMeta, sandboxEnv?: SandboxEnvironment): boolean {
  const nodeType = node?.nodeName?.toLowerCase?.() || '';
  if (nodeType === 'script') {
    routeScriptNodeThroughSandbox(node, sandboxEnv);
    return true;
  }
  if (forbiddenElements.includes(nodeType)) {
    logWarning(`Plugin ${meta.id} tried to insert ${nodeType}`, {
      pluginId: meta.id,
      attrOrMethod: 'insert',
      param: nodeType,
      entity: 'HTMLElement',
    });
    return true;
  }
  return false;
}

function distortInsert(distortions: DistortionMap) {
  // Node.insertBefore(node, ref) and Node.replaceChild(node, old): the new node
  // is the first argument.
  function getInsertDistortion(originalMethod: unknown, meta: SandboxPluginMeta, sandboxEnv?: SandboxEnvironment) {
    return function insertChildDistortion(this: unknown, node?: Node, ref?: Node) {
      if (node && shouldBlockHostInsertion(node, meta, sandboxEnv)) {
        return document.createDocumentFragment();
      }
      if (isFunction(originalMethod)) {
        return originalMethod.call(this, node, ref);
      }
    };
  }

  function getinsertAdjacentElementDistortion(
    originalMethod: unknown,
    meta: SandboxPluginMeta,
    sandboxEnv?: SandboxEnvironment
  ) {
    return function insertAdjacentElementDistortion(this: Element, position?: string, node?: Node) {
      if (node && shouldBlockHostInsertion(node, meta, sandboxEnv)) {
        return document.createDocumentFragment();
      }
      if (isFunction(originalMethod)) {
        return originalMethod.call(this, position, node);
      }
    };
  }

  const descriptors = [
    Object.getOwnPropertyDescriptor(Node.prototype, 'insertBefore'),
    Object.getOwnPropertyDescriptor(Node.prototype, 'replaceChild'),
    // Range.insertNode(node) attaches a node to the document and would otherwise
    // run a <script> in the host page.
    Object.getOwnPropertyDescriptor(Range.prototype, 'insertNode'),
  ];

  for (const descriptor of descriptors) {
    if (descriptor?.value) {
      distortions.set(descriptor.value, getInsertDistortion);
    }
  }

  const descriptorAdjacent = Object.getOwnPropertyDescriptor(Element.prototype, 'insertAdjacentElement');
  if (descriptorAdjacent?.value) {
    distortions.set(descriptorAdjacent.value, getinsertAdjacentElementDistortion);
  }
}

// set distortions to append elements to the document
function distortAppend(distortions: DistortionMap) {
  // append accepts an array of nodes to append https://developer.mozilla.org/en-US/docs/Web/API/Node/append
  function getAppendDistortion(originalMethod: unknown, meta: SandboxPluginMeta, sandboxEnv?: SandboxEnvironment) {
    return function appendDistortion(this: HTMLElement, ...args: Array<Node | string>) {
      // Strings are inserted as text nodes, never parsed as HTML, so they are
      // safe to forward. Element nodes go through the shared insertion guard that
      // drops forbidden elements and routes scripts into the sandbox.
      const acceptedNodes = args.filter(
        (node): boolean => typeof node === 'string' || !shouldBlockHostInsertion(node, meta, sandboxEnv)
      );

      if (isFunction(originalMethod)) {
        originalMethod.apply(this, acceptedNodes);
      }
      // https://developer.mozilla.org/en-US/docs/Web/API/Element/append#return_value
      return undefined;
    };
  }

  // appendChild accepts a single node to add https://developer.mozilla.org/en-US/docs/Web/API/Node/appendChild
  function getAppendChildDistortion(originalMethod: unknown, meta: SandboxPluginMeta, sandboxEnv?: SandboxEnvironment) {
    return function appendChildDistortion(this: HTMLElement, arg?: Node) {
      // Forbidden elements are dropped and scripts are re-loaded inside the
      // sandbox (so webpack chunks keep working) rather than running in the host.
      if (arg && shouldBlockHostInsertion(arg, meta, sandboxEnv)) {
        return document.createDocumentFragment();
      }
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

  // document.write/writeln parse their argument as HTML in the host document,
  // so they are blocked outright the same way.
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
