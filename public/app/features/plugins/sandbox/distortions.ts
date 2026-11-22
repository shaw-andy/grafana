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
    distortInnerHTML(generalDistortionMap);
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

function distortInnerHTML(distortions: DistortionMap) {
  function getInnerHTMLDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    const pluginId = meta.id;
    return function innerHTMLDistortion(this: HTMLElement, ...args: string[]) {
      for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        // NOTE: DOMPurify anti-tamper mechanism requires us to clone the string
        // calling any method whatsoever on a string will cause the string to be tampered
        // and DOMPurify will return empty strings
        const lowerCase = String(arg || '').toLowerCase();
        for (const forbiddenElement of forbiddenElements) {
          if (lowerCase.includes('<' + forbiddenElement)) {
            logWarning(`Plugin ${pluginId} tried to set ${forbiddenElement} in innerHTML`, {
              pluginId,
              attrOrMethod: 'innerHTML',
              param: forbiddenElement,
              entity: 'HTMLElement',
            });

            throw new Error('<' + forbiddenElement + '> is not allowed in sandboxed plugins');
          }
        }
        // prevent some dom operations that use direct callbacks
        if (lowerCase.match(/onerror|onload|onsuccess|onbeforeunload/)) {
          logWarning(`Plugin ${pluginId} tried to set forbidden attribute in innerHTML`, {
            pluginId,
            attrOrMethod: 'innerHTML',
            param: arg,
            entity: 'HTMLElement',
          });
          args[i] = DOMPurify.sanitize(args[i]);
        }
      }

      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, args);
      }
    };
  }
  const descriptors = [
    Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML'),
    Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML'),
    Object.getOwnPropertyDescriptor(Element.prototype, 'insertAdjacentHTML'),
    Object.getOwnPropertyDescriptor(Element.prototype, 'setHTMLUnsafe'),
    globalThis.ShadowRoot && Object.getOwnPropertyDescriptor(ShadowRoot.prototype, 'innerHTML'),
    globalThis.ShadowRoot && Object.getOwnPropertyDescriptor(ShadowRoot.prototype, 'setHTMLUnsafe'),
    Object.getOwnPropertyDescriptor(Document, 'parseHTMLUnsafe'),
    Object.getOwnPropertyDescriptor(Document.prototype, 'execCommand'),
    Object.getOwnPropertyDescriptor(DOMParser.prototype, 'parseFromString'),
  ];

  for (const descriptor of descriptors) {
    if (descriptor?.set) {
      distortions.set(descriptor.set, getInnerHTMLDistortion);
    }
    if (descriptor?.value) {
      distortions.set(descriptor.value, getInnerHTMLDistortion);
    }
  }

  // unlike innerHTML, scripts in a contextual fragment run once the fragment is connected
  function getCreateContextualFragmentDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    const createContextualFragment = getInnerHTMLDistortion(originalMethod, meta);
    return function createContextualFragmentDistortion(this: HTMLElement, ...args: string[]) {
      const fragment = createContextualFragment.apply(this, args);
      removeScriptElements(fragment);
      return fragment;
    };
  }
  const contextualFragmentDescriptor = globalThis.Range
    ? Object.getOwnPropertyDescriptor(Range.prototype, 'createContextualFragment')
    : undefined;
  if (contextualFragmentDescriptor?.value) {
    distortions.set(contextualFragmentDescriptor.value, getCreateContextualFragmentDistortion);
  }
}

const HTML_NAMESPACE = 'http://www.w3.org/1999/xhtml';
const SVG_NAMESPACE = 'http://www.w3.org/2000/svg';

/**
 * Creates a script element that never runs, wherever it is inserted later.
 *
 * Connecting a script with source text to a document without a browsing context marks it as
 * "already started" without running it. That flag is kept when the script is adopted, modified or
 * cloned, so DOM APIs called outside of the sandbox (e.g. by libraries plugins pass the element to)
 * cannot run it in the page either.
 */
function createInertScriptElement(ownerDocument: unknown, namespace: string): Element {
  const inertDocument = document.implementation.createHTMLDocument('');
  const script =
    namespace === SVG_NAMESPACE
      ? inertDocument.createElementNS(SVG_NAMESPACE, 'script')
      : inertDocument.createElement('script');
  script.appendChild(inertDocument.createTextNode(' '));
  inertDocument.body.appendChild(script);
  script.remove();
  script.textContent = '';
  const targetDocument = ownerDocument instanceof Document ? ownerDocument : document;
  return targetDocument.adoptNode(script);
}

function logForbiddenElementCreation(name: string, method: string, meta: SandboxPluginMeta) {
  logWarning(`Plugin ${meta.id} tried to create ${name}`, {
    pluginId: meta.id,
    attrOrMethod: method,
    param: name,
    entity: 'document',
  });
}

function distortCreateElement(distortions: DistortionMap) {
  function getCreateElementDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    return function createElementDistortion(this: Document, arg?: string, options?: unknown) {
      const tagName = String(arg);
      const name = tagName.toLowerCase();
      if (forbiddenElements.includes(name)) {
        logForbiddenElementCreation(name, 'createElement', meta);
        return document.createDocumentFragment();
      }
      if (name === 'script') {
        return createInertScriptElement(this, HTML_NAMESPACE);
      }
      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, [tagName, options]);
      }
    };
  }

  function getCreateElementNSDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    return function createElementNSDistortion(
      this: Document,
      namespaceArg?: string | null,
      qualifiedNameArg?: string,
      options?: unknown
    ) {
      // arguments are converted once so the checked values are the ones passed to the native method
      const namespace = namespaceArg === null || namespaceArg === undefined ? null : String(namespaceArg);
      const qualifiedName = String(qualifiedNameArg);
      const name = qualifiedName.slice(qualifiedName.indexOf(':') + 1).toLowerCase();
      if (forbiddenElements.includes(name)) {
        logForbiddenElementCreation(name, 'createElementNS', meta);
        return document.createDocumentFragment();
      }
      if (name === 'script' && (namespace === HTML_NAMESPACE || namespace === SVG_NAMESPACE)) {
        return createInertScriptElement(this, namespace);
      }
      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, [namespace, qualifiedName, options]);
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

// Native getters are captured once so plugin code cannot influence the subtree walk below
// by shadowing DOM properties on the nodes it passes in.
function getNativeGetter(proto: object | undefined, property: string) {
  return proto ? Object.getOwnPropertyDescriptor(proto, property)?.get : undefined;
}
const nativeNodeType = getNativeGetter(Node.prototype, 'nodeType');
const nativeFirstChild = getNativeGetter(Node.prototype, 'firstChild');
const nativeNextSibling = getNativeGetter(Node.prototype, 'nextSibling');
const nativeLocalName = getNativeGetter(Element.prototype, 'localName');
const nativeShadowRoot = getNativeGetter(Element.prototype, 'shadowRoot');
const nativeTemplateContent = getNativeGetter(globalThis.HTMLTemplateElement?.prototype, 'content');
const nativeRemove = Element.prototype.remove;

function callNativeGetter(getter: (() => unknown) | undefined, target: unknown): unknown {
  return getter ? Reflect.apply(getter, target, []) : undefined;
}

function getNodeType(value: unknown): number | undefined {
  if (typeof value !== 'object' || value === null) {
    return undefined;
  }
  try {
    const nodeType = callNativeGetter(nativeNodeType, value);
    return typeof nodeType === 'number' ? nodeType : undefined;
  } catch (e) {
    // not a DOM node, native insertion methods convert it to a text node
    return undefined;
  }
}

function isElementNode(value: unknown): value is Element {
  return getNodeType(value) === Node.ELEMENT_NODE;
}

/**
 * Calls visit for every element in the node, its descendants, open shadow roots and template contents
 * until visit returns true. Scripts can run in the page from any of those places once the node
 * is connected, so the whole tree has to be checked and not only the node itself.
 */
function walkElements(node: unknown, visit: (element: Element, name: string) => boolean | void) {
  if (getNodeType(node) === undefined) {
    return;
  }
  const pending: unknown[] = [node];
  while (pending.length > 0) {
    const current = pending.pop();
    if (isElementNode(current)) {
      const element = current;
      const name = String(callNativeGetter(nativeLocalName, element)).toLowerCase();
      if (visit(element, name)) {
        return;
      }
      const shadowRoot = callNativeGetter(nativeShadowRoot, element);
      if (shadowRoot) {
        pending.push(shadowRoot);
      }
      if (name === 'template') {
        try {
          pending.push(callNativeGetter(nativeTemplateContent, element));
        } catch (e) {
          // not an HTML template element
        }
      }
    }
    let child = callNativeGetter(nativeFirstChild, current);
    while (child) {
      pending.push(child);
      child = callNativeGetter(nativeNextSibling, child);
    }
  }
}

function findForbiddenElement(node: unknown): string | undefined {
  let forbiddenElement: string | undefined;
  walkElements(node, (_element, name) => {
    if (name === 'script' || forbiddenElements.includes(name)) {
      forbiddenElement = name;
      return true;
    }
    return false;
  });
  return forbiddenElement;
}

function removeScriptElements(node: unknown) {
  const scripts: Element[] = [];
  walkElements(node, (element, name) => {
    if (name === 'script') {
      scripts.push(element);
    }
  });
  for (const script of scripts) {
    Reflect.apply(nativeRemove, script, []);
  }
}

// Scripts are never handed to the native DOM method. Their src is evaluated inside the sandbox
// instead, which is how webpack chunks of sandboxed plugins get loaded.
// loadScriptIntoSandbox has restrictions on what scripts can be loaded
function loadScriptElementIntoSandbox(script: HTMLScriptElement, sandboxEnv: SandboxEnvironment) {
  loadScriptIntoSandbox(script.src, sandboxEnv)
    .then(() => {
      script.onload?.call(script, new Event('load'));
    })
    .catch((err) => {
      script.onerror?.call(script, new ErrorEvent('error', { error: err }));
    });
}

/**
 * Returns true when the node can be passed to a native DOM insertion method.
 * Otherwise the node is refused and, if it is a script element, loaded into the sandbox.
 */
function isAllowedToInsert(
  node: unknown,
  method: string,
  meta: SandboxPluginMeta,
  sandboxEnv?: SandboxEnvironment
): boolean {
  const forbiddenElement = findForbiddenElement(node);
  if (forbiddenElement === undefined) {
    return true;
  }

  if (node instanceof HTMLScriptElement && sandboxEnv) {
    loadScriptElementIntoSandbox(node, sandboxEnv);
    return false;
  }

  logWarning(`Plugin ${meta.id} tried to insert ${forbiddenElement}`, {
    pluginId: meta.id,
    attrOrMethod: method,
    param: forbiddenElement,
    entity: 'HTMLElement',
  });
  return false;
}

// set distortions for every DOM API that inserts a single node into a tree
function distortInsert(distortions: DistortionMap) {
  function getSingleNodeInsertDistortion(method: string, nodeArgIndex: number) {
    return function (originalMethod: unknown, meta: SandboxPluginMeta, sandboxEnv?: SandboxEnvironment) {
      return function insertNodeDistortion(this: unknown, ...args: unknown[]) {
        if (!isAllowedToInsert(args[nodeArgIndex], method, meta, sandboxEnv)) {
          return method === 'appendChild' ? undefined : document.createDocumentFragment();
        }
        if (isFunction(originalMethod)) {
          return originalMethod.apply(this, args);
        }
      };
    };
  }

  const singleNodeMethods: Array<[object | undefined, string, number]> = [
    [Node.prototype, 'appendChild', 0],
    [Node.prototype, 'insertBefore', 0],
    [Node.prototype, 'replaceChild', 0],
    [Element.prototype, 'insertAdjacentElement', 1],
    [Element.prototype, 'moveBefore', 0],
    [Document.prototype, 'moveBefore', 0],
    [DocumentFragment.prototype, 'moveBefore', 0],
    [globalThis.Range?.prototype, 'insertNode', 0],
    [globalThis.Range?.prototype, 'surroundContents', 0],
  ];

  for (const [proto, method, nodeArgIndex] of singleNodeMethods) {
    const descriptor = proto ? Object.getOwnPropertyDescriptor(proto, method) : undefined;
    if (descriptor?.value) {
      distortions.set(descriptor.value, getSingleNodeInsertDistortion(method, nodeArgIndex));
    }
  }
}

// set distortions for every DOM API that inserts a list of nodes into a tree
// e.g. append https://developer.mozilla.org/en-US/docs/Web/API/Element/append
function distortAppend(distortions: DistortionMap) {
  const replacingMethods = ['replaceChildren', 'replaceWith'];

  function getMultipleNodesInsertDistortion(method: string) {
    return function (originalMethod: unknown, meta: SandboxPluginMeta, sandboxEnv?: SandboxEnvironment) {
      return function insertNodesDistortion(this: unknown, ...args: unknown[]) {
        const acceptedNodes = args.filter((node) => isAllowedToInsert(node, method, meta, sandboxEnv));
        // replacing with only part of the requested nodes would remove content the plugin never got to replace
        if (acceptedNodes.length !== args.length && replacingMethods.includes(method)) {
          return undefined;
        }
        if (isFunction(originalMethod)) {
          originalMethod.apply(this, acceptedNodes);
        }
        // https://developer.mozilla.org/en-US/docs/Web/API/Element/append#return_value
        return undefined;
      };
    };
  }

  const parentNodeMethods = ['append', 'prepend', 'replaceChildren'];
  const childNodeMethods = ['before', 'after', 'replaceWith'];
  const targets: Array<[object | undefined, string[]]> = [
    [Element.prototype, [...parentNodeMethods, ...childNodeMethods]],
    [Document.prototype, parentNodeMethods],
    [DocumentFragment.prototype, parentNodeMethods],
    [CharacterData.prototype, childNodeMethods],
    [globalThis.DocumentType?.prototype, childNodeMethods],
  ];

  for (const [proto, methods] of targets) {
    for (const method of methods) {
      const descriptor = proto ? Object.getOwnPropertyDescriptor(proto, method) : undefined;
      if (descriptor?.value) {
        distortions.set(descriptor.value, getMultipleNodesInsertDistortion(method));
      }
    }
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
