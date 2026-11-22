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

type Distortion = (
  originalAttrOrMethod: unknown,
  pluginMeta: SandboxPluginMeta,
  sandboxEnv?: SandboxEnvironment
) => unknown;
type DistortionMap = Map<unknown, Distortion>;
const generalDistortionMap: DistortionMap = new Map();

const SANDBOX_LIVE_API_PATCHED = Symbol.for('@SANDBOX_LIVE_API_PATCHED');

// Elements a plugin may never insert into a document: they would run code outside the sandbox.
const executableElements = [...forbiddenElements, 'script'];
const executableElementsSelector = executableElements.join(',');

// Captured before any plugin code runs so the checks below can't be redirected from inside the sandbox.
const nativeNodeTypeGetter = Object.getOwnPropertyDescriptor(Node.prototype, 'nodeType')?.get;
const nativeLocalNameGetter = Object.getOwnPropertyDescriptor(Element.prototype, 'localName')?.get;
const nativeQuerySelectors = [
  Element.prototype.querySelector,
  DocumentFragment.prototype.querySelector,
  Document.prototype.querySelector,
];

export function getGeneralSandboxDistortionMap() {
  if (generalDistortionMap.size === 0) {
    // initialize the distortion map
    distortIframeAttributes(generalDistortionMap);
    distortConsole(generalDistortionMap);
    distortAlert(generalDistortionMap);
    distortNodeInsertion(generalDistortionMap);
    distortInnerHTML(generalDistortionMap);
    distortCreateContextualFragment(generalDistortionMap);
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

function callNative(fn: Function | undefined, target: unknown, args: unknown[] = []): unknown {
  if (!fn) {
    return undefined;
  }
  try {
    return Reflect.apply(fn, target, args);
  } catch (e) {
    return undefined;
  }
}

function isNode(value: unknown): value is Node {
  return typeof value === 'object' && value !== null && callNative(nativeNodeTypeGetter, value) !== undefined;
}

function getLocalName(value: unknown): string | undefined {
  const localName = callNative(nativeLocalNameGetter, value);
  return typeof localName === 'string' ? localName.toLowerCase() : undefined;
}

/**
 * Returns the name of the first script or forbidden element found in `node` or any of its descendants
 * (including the children of a DocumentFragment), or undefined if there is none.
 */
function findExecutableElement(node: unknown): string | undefined {
  if (!isNode(node)) {
    return undefined;
  }
  const localName = getLocalName(node);
  if (localName && executableElements.includes(localName)) {
    return localName;
  }
  for (const querySelector of nativeQuerySelectors) {
    const match = callNative(querySelector, node, [executableElementsSelector]);
    if (match) {
      return getLocalName(match) ?? 'script';
    }
  }
  return undefined;
}

function rejectExecutableElements(nodes: unknown[], meta: SandboxPluginMeta, attrOrMethod: string) {
  for (const node of nodes) {
    const elementName = findExecutableElement(node);
    if (elementName) {
      logWarning(`Plugin ${meta.id} tried to insert ${elementName}`, {
        pluginId: meta.id,
        attrOrMethod,
        param: elementName,
        entity: 'HTMLElement',
      });
      throw new Error('<' + elementName + '> is not allowed in sandboxed plugins');
    }
  }
}

// Strings are converted here, once, so that no plugin code (e.g. a custom toString) can run between
// the check and the native call and swap in a different node.
function toNodesOrStrings(args: unknown[]): unknown[] {
  return args.map((arg) => (isNode(arg) ? arg : String(arg)));
}

function isTrustedHTML(value: unknown): boolean {
  return Boolean(window.trustedTypes?.isHTML(value));
}

function toHTMLArgument(arg: unknown): unknown {
  if ((typeof arg === 'object' && arg !== null) || typeof arg === 'function') {
    return isTrustedHTML(arg) ? arg : String(arg);
  }
  return arg;
}

function createHTMLStringDistortion(blockedElements: string[]) {
  return function getHTMLStringDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    const pluginId = meta.id;
    return function htmlStringDistortion(this: unknown, ...originalArgs: unknown[]) {
      const args = originalArgs.map(toHTMLArgument);
      for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        // NOTE: DOMPurify anti-tamper mechanism requires us to clone the string
        // calling any method whatsoever on a string will cause the string to be tampered
        // and DOMPurify will return empty strings
        const lowerCase = String(arg || '').toLowerCase();
        for (const blockedElement of blockedElements) {
          if (lowerCase.includes('<' + blockedElement)) {
            logWarning(`Plugin ${pluginId} tried to set ${blockedElement} in innerHTML`, {
              pluginId,
              attrOrMethod: 'innerHTML',
              param: blockedElement,
              entity: 'HTMLElement',
            });

            throw new Error('<' + blockedElement + '> is not allowed in sandboxed plugins');
          }
        }
        // prevent some dom operations that use direct callbacks
        if (lowerCase.match(/onerror|onload|onsuccess|onbeforeunload/)) {
          logWarning(`Plugin ${pluginId} tried to set forbidden attribute in innerHTML`, {
            pluginId,
            attrOrMethod: 'innerHTML',
            param: String(arg),
            entity: 'HTMLElement',
          });
          args[i] = DOMPurify.sanitize(String(arg));
        }
      }

      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, args);
      }
    };
  };
}

function distortInnerHTML(distortions: DistortionMap) {
  const getInnerHTMLDistortion = createHTMLStringDistortion(forbiddenElements);
  const descriptors = [
    Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML'),
    Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML'),
    Object.getOwnPropertyDescriptor(Element.prototype, 'insertAdjacentHTML'),
    Object.getOwnPropertyDescriptor(Element.prototype, 'setHTMLUnsafe'),
    Object.getOwnPropertyDescriptor(ShadowRoot.prototype, 'innerHTML'),
    Object.getOwnPropertyDescriptor(ShadowRoot.prototype, 'setHTMLUnsafe'),
    Object.getOwnPropertyDescriptor(DOMParser.prototype, 'parseFromString'),
    Object.getOwnPropertyDescriptor(Document, 'parseHTMLUnsafe'),
  ];

  for (const descriptor of descriptors) {
    if (descriptor?.set) {
      distortions.set(descriptor.set, getInnerHTMLDistortion);
    }
    if (descriptor?.value) {
      distortions.set(descriptor.value, getInnerHTMLDistortion);
    }
  }
}

// Unlike innerHTML, scripts parsed by createContextualFragment run once the fragment is inserted.
function distortCreateContextualFragment(distortions: DistortionMap) {
  const descriptor = Object.getOwnPropertyDescriptor(Range.prototype, 'createContextualFragment');
  if (descriptor?.value) {
    distortions.set(descriptor.value, createHTMLStringDistortion(executableElements));
  }
}

function distortCreateElement(distortions: DistortionMap) {
  function rejectForbiddenElement(localName: string, meta: SandboxPluginMeta, attrOrMethod: string) {
    const lowerCaseName = localName.toLowerCase();
    if (forbiddenElements.includes(lowerCaseName)) {
      logWarning(`Plugin ${meta.id} tried to create ${lowerCaseName}`, {
        pluginId: meta.id,
        attrOrMethod,
        param: lowerCaseName,
        entity: 'document',
      });
      return true;
    }
    return false;
  }

  function getCreateElementDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    return function createElementDistortion(this: Document, arg?: unknown, options?: unknown) {
      const localName = String(arg);
      if (rejectForbiddenElement(localName, meta, 'createElement')) {
        return document.createDocumentFragment();
      }
      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, [localName, options]);
      }
    };
  }

  function getCreateElementNSDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    return function createElementNSDistortion(
      this: Document,
      namespace?: unknown,
      qualifiedName?: unknown,
      options?: unknown
    ) {
      const boundNamespace = namespace === null || namespace === undefined ? null : String(namespace);
      const boundQualifiedName = String(qualifiedName);
      const localName = boundQualifiedName.slice(boundQualifiedName.indexOf(':') + 1);
      if (rejectForbiddenElement(localName, meta, 'createElementNS')) {
        return document.createDocumentFragment();
      }
      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, [boundNamespace, boundQualifiedName, options]);
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

/**
 * Every DOM API that inserts a caller-provided node goes through here. A script or forbidden element
 * (or a node containing one) would run outside the sandbox once connected, so it is rejected before
 * the native method is called. The only exception is a script element passed directly to appendChild
 * or insertBefore, which is how bundlers load chunks: it is loaded into the sandbox instead.
 */
function distortNodeInsertion(distortions: DistortionMap) {
  function getNodesOrStringsDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    return function nodesOrStringsDistortion(this: Node, ...originalArgs: unknown[]) {
      const args = toNodesOrStrings(originalArgs);
      rejectExecutableElements(args, meta, 'append');
      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, args);
      }
    };
  }

  function loadScriptElementIntoSandbox(script: HTMLScriptElement, sandboxEnv: SandboxEnvironment) {
    loadScriptIntoSandbox(script.src, sandboxEnv)
      .then(() => {
        script.onload?.call(script, new Event('load'));
      })
      .catch((err) => {
        script.onerror?.call(script, new ErrorEvent('error', { error: err }));
      });
  }

  // appendChild accepts a single node to add https://developer.mozilla.org/en-US/docs/Web/API/Node/appendChild
  function getAppendChildDistortion(originalMethod: unknown, meta: SandboxPluginMeta, sandboxEnv?: SandboxEnvironment) {
    return function appendChildDistortion(this: Node, node?: unknown) {
      // loadScriptIntoSandbox has restrictions on what scripts can be loaded
      if (sandboxEnv && node instanceof HTMLScriptElement && getLocalName(node) === 'script') {
        loadScriptElementIntoSandbox(node, sandboxEnv);
        return node;
      }
      rejectExecutableElements([node], meta, 'appendChild');
      if (isFunction(originalMethod)) {
        return originalMethod.call(this, node);
      }
    };
  }

  function getInsertBeforeDistortion(
    originalMethod: unknown,
    meta: SandboxPluginMeta,
    sandboxEnv?: SandboxEnvironment
  ) {
    return function insertBeforeDistortion(this: Node, node?: unknown, child?: unknown) {
      if (sandboxEnv && node instanceof HTMLScriptElement && getLocalName(node) === 'script') {
        loadScriptElementIntoSandbox(node, sandboxEnv);
        return node;
      }
      rejectExecutableElements([node], meta, 'insertBefore');
      if (isFunction(originalMethod)) {
        return originalMethod.call(this, node, child);
      }
    };
  }

  function getReplaceChildDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    return function replaceChildDistortion(this: Node, node?: unknown, child?: unknown) {
      rejectExecutableElements([node], meta, 'replaceChild');
      if (isFunction(originalMethod)) {
        return originalMethod.call(this, node, child);
      }
    };
  }

  function getInsertAdjacentElementDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    return function insertAdjacentElementDistortion(this: Element, position?: unknown, element?: unknown) {
      const boundPosition = String(position);
      rejectExecutableElements([element], meta, 'insertAdjacentElement');
      if (isFunction(originalMethod)) {
        return originalMethod.call(this, boundPosition, element);
      }
    };
  }

  function getRangeInsertionDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    return function rangeInsertionDistortion(this: Range, node?: unknown) {
      rejectExecutableElements([node], meta, 'Range');
      if (isFunction(originalMethod)) {
        return originalMethod.call(this, node);
      }
    };
  }

  // ParentNode and ChildNode methods accept any mix of nodes and strings
  // https://developer.mozilla.org/en-US/docs/Web/API/Element/append
  const nodesOrStringsMethods: Array<[object, string[]]> = [
    [Element.prototype, ['append', 'prepend', 'replaceChildren', 'before', 'after', 'replaceWith']],
    [CharacterData.prototype, ['before', 'after', 'replaceWith']],
    [DocumentType.prototype, ['before', 'after', 'replaceWith']],
    [Document.prototype, ['append', 'prepend', 'replaceChildren']],
    [DocumentFragment.prototype, ['append', 'prepend', 'replaceChildren']],
  ];
  for (const [prototype, methods] of nodesOrStringsMethods) {
    for (const method of methods) {
      const descriptor = Object.getOwnPropertyDescriptor(prototype, method);
      if (descriptor?.value) {
        distortions.set(descriptor.value, getNodesOrStringsDistortion);
      }
    }
  }

  const singleNodeMethods: Array<[object, string, Distortion]> = [
    [Node.prototype, 'appendChild', getAppendChildDistortion],
    [Node.prototype, 'insertBefore', getInsertBeforeDistortion],
    [Node.prototype, 'replaceChild', getReplaceChildDistortion],
    [Element.prototype, 'insertAdjacentElement', getInsertAdjacentElementDistortion],
    [Range.prototype, 'insertNode', getRangeInsertionDistortion],
    [Range.prototype, 'surroundContents', getRangeInsertionDistortion],
  ];
  for (const [prototype, method, distortion] of singleNodeMethods) {
    const descriptor = Object.getOwnPropertyDescriptor(prototype, method);
    if (descriptor?.value) {
      distortions.set(descriptor.value, distortion);
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
