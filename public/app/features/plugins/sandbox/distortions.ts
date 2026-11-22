import { type ProxyTarget } from '@locker/near-membrane-shared';
import { cloneDeep, isFunction } from 'lodash';

import { type Monaco } from '@grafana/ui';

import { loadScriptIntoSandbox } from './codeLoader';
import { forbiddenElements } from './constants';
import { recursivePatchObjectAsLiveTarget } from './documentSandbox';
import {
  documentParser,
  findForbiddenInsertedElement,
  ForbiddenElementError,
  getElementLocalName,
  getFragmentParser,
  getParentNode,
  getShadowRootHost,
  isElementNode,
  isHTMLScriptElement,
  isInHTMLDocument,
  isNode,
  sanitizeMarkup,
  sanitizeTree,
} from './domSafety';
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

export function getGeneralSandboxDistortionMap() {
  if (generalDistortionMap.size === 0) {
    // initialize the distortion map
    distortIframeAttributes(generalDistortionMap);
    distortConsole(generalDistortionMap);
    distortAlert(generalDistortionMap);
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

function logForbiddenElement(pluginId: string, element: string, attrOrMethod: string) {
  logWarning(`Plugin ${pluginId} tried to use ${element} in ${attrOrMethod}`, {
    pluginId,
    attrOrMethod,
    param: element,
    entity: 'HTMLElement',
  });
}

// Markup is converted to a string exactly once, and that string is checked, sanitized and handed
// to the browser, so a value whose toString changes between calls cannot pass the check and parse differently.
function toMarkupString(value: unknown): string {
  return value === null || value === undefined ? '' : String(value);
}

function sanitizeMarkupForPlugin(
  markup: string,
  parser: ReturnType<typeof getFragmentParser>,
  pluginId: string,
  attrOrMethod: string
): string {
  try {
    return sanitizeMarkup(markup, parser);
  } catch (e) {
    if (e instanceof ForbiddenElementError) {
      logForbiddenElement(pluginId, e.element, attrOrMethod);
    }
    throw e;
  }
}

function sanitizeParsedTreeForPlugin(result: unknown, pluginId: string, attrOrMethod: string) {
  if (!isNode(result)) {
    return;
  }
  const { forbiddenElement } = sanitizeTree(result);
  if (forbiddenElement) {
    logForbiddenElement(pluginId, forbiddenElement, attrOrMethod);
    throw new ForbiddenElementError(forbiddenElement);
  }
}

type FragmentContext = (target: unknown, args: unknown[]) => Element | null;

function contextElement(node: unknown): Element | null {
  return isElementNode(node) ? node : null;
}

// innerHTML of a shadow root is parsed with its host as context
const targetContext: FragmentContext = (target) => getShadowRootHost(target) ?? contextElement(target);
const parentContext: FragmentContext = (target) => (isNode(target) ? contextElement(getParentNode(target)) : null);
const insertAdjacentContext: FragmentContext = (target, args) => {
  // the browser must receive the same position the context was chosen for
  const position = toMarkupString(args[0]);
  args[0] = position;
  const lowerCasePosition = position.toLowerCase();
  const context =
    lowerCasePosition === 'beforebegin' || lowerCasePosition === 'afterend'
      ? parentContext(target, args)
      : contextElement(target);
  // insertAdjacentHTML parses with a <body> context in place of <html>
  return context && getElementLocalName(context) === 'html' ? null : context;
};

function distortInnerHTML(distortions: DistortionMap) {
  // sinks that parse markup into a node that is, or can later become, part of the live document
  function getHTMLSinkDistortion(
    attrOrMethod: string,
    markupArgIndex: number,
    getContext: FragmentContext,
    allowsDeclarativeShadowRoots = false
  ) {
    return function (originalMethod: unknown, meta: SandboxPluginMeta) {
      const pluginId = meta.id;
      return function htmlSinkDistortion(this: unknown, ...args: unknown[]) {
        if (!isFunction(originalMethod)) {
          return undefined;
        }
        const markup = toMarkupString(args[markupArgIndex]);
        // XML documents parse fragments with the XML parser and never have a browsing context,
        // so their result is cleaned after parsing instead
        const isXmlTarget = !isInHTMLDocument(this);
        if (!isXmlTarget || allowsDeclarativeShadowRoots) {
          args[markupArgIndex] = sanitizeMarkupForPlugin(
            markup,
            getFragmentParser(getContext(this, args)),
            pluginId,
            attrOrMethod
          );
        } else {
          args[markupArgIndex] = markup;
        }
        const parent = isXmlTarget && isNode(this) ? getParentNode(this) : null;
        const result = originalMethod.apply(this, args);
        if (isXmlTarget) {
          sanitizeParsedTreeForPlugin(parent ?? this, pluginId, attrOrMethod);
        }
        return result;
      };
    };
  }

  // static Document parsers that return a new document
  function getDocumentParserDistortion(attrOrMethod: string) {
    return function (originalMethod: unknown, meta: SandboxPluginMeta) {
      const pluginId = meta.id;
      return function documentParserDistortion(this: unknown, ...args: unknown[]) {
        if (!isFunction(originalMethod)) {
          return undefined;
        }
        args[0] = sanitizeMarkupForPlugin(toMarkupString(args[0]), documentParser, pluginId, attrOrMethod);
        const result = originalMethod.apply(this, args);
        sanitizeParsedTreeForPlugin(result, pluginId, attrOrMethod);
        return result;
      };
    };
  }

  // parsers that return a detached document or fragment, which is cleaned before the plugin gets it
  function getParserDistortion(attrOrMethod: string, markupArgIndex?: number) {
    return function (originalMethod: unknown, meta: SandboxPluginMeta) {
      const pluginId = meta.id;
      return function parserDistortion(this: unknown, ...args: unknown[]) {
        if (!isFunction(originalMethod)) {
          return undefined;
        }
        if (markupArgIndex !== undefined) {
          args[markupArgIndex] = toMarkupString(args[markupArgIndex]);
        }
        const result = originalMethod.apply(this, args);
        sanitizeParsedTreeForPlugin(result, pluginId, attrOrMethod);
        return result;
      };
    };
  }

  // documents parsed from a network response
  function getResponseDocumentDistortion(attrOrMethod: string) {
    return function (originalGetter: unknown, meta: SandboxPluginMeta) {
      const pluginId = meta.id;
      return function responseDocumentDistortion(this: unknown) {
        if (!isFunction(originalGetter)) {
          return undefined;
        }
        const result = originalGetter.call(this);
        if (isNode(result) && result.nodeType === Node.DOCUMENT_NODE) {
          const { forbiddenElement } = sanitizeTree(result);
          if (forbiddenElement) {
            logForbiddenElement(pluginId, forbiddenElement, attrOrMethod);
          }
        }
        return result;
      };
    };
  }

  function getExecCommandDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    const pluginId = meta.id;
    return function execCommandDistortion(this: Document, ...args: unknown[]) {
      if (!isFunction(originalMethod)) {
        return undefined;
      }
      const command = toMarkupString(args[0]);
      args[0] = command;
      if (command.toLowerCase() === 'inserthtml') {
        args[2] = sanitizeMarkupForPlugin(toMarkupString(args[2]), getFragmentParser(null), pluginId, 'execCommand');
      }
      return originalMethod.apply(this, args);
    };
  }

  const shadowRootProto = typeof ShadowRoot === 'undefined' ? undefined : ShadowRoot.prototype;
  const sinks: Array<[object | undefined, string, Distortion]> = [
    [Element.prototype, 'innerHTML', getHTMLSinkDistortion('innerHTML', 0, targetContext)],
    [Element.prototype, 'outerHTML', getHTMLSinkDistortion('outerHTML', 0, parentContext)],
    [Element.prototype, 'insertAdjacentHTML', getHTMLSinkDistortion('insertAdjacentHTML', 1, insertAdjacentContext)],
    [Element.prototype, 'setHTMLUnsafe', getHTMLSinkDistortion('setHTMLUnsafe', 0, targetContext, true)],
    [Element.prototype, 'setHTML', getHTMLSinkDistortion('setHTML', 0, targetContext, true)],
    [shadowRootProto, 'innerHTML', getHTMLSinkDistortion('innerHTML', 0, targetContext)],
    [shadowRootProto, 'setHTMLUnsafe', getHTMLSinkDistortion('setHTMLUnsafe', 0, targetContext, true)],
    [shadowRootProto, 'setHTML', getHTMLSinkDistortion('setHTML', 0, targetContext, true)],
    [Document, 'parseHTMLUnsafe', getDocumentParserDistortion('parseHTMLUnsafe')],
    [Document, 'parseHTML', getDocumentParserDistortion('parseHTML')],
    [Document.prototype, 'execCommand', getExecCommandDistortion],
    [DOMParser.prototype, 'parseFromString', getParserDistortion('parseFromString', 0)],
    [Range.prototype, 'createContextualFragment', getParserDistortion('createContextualFragment', 0)],
    [XMLHttpRequest.prototype, 'responseXML', getResponseDocumentDistortion('responseXML')],
    [XMLHttpRequest.prototype, 'response', getResponseDocumentDistortion('response')],
  ];
  if (typeof XSLTProcessor !== 'undefined') {
    sinks.push(
      [XSLTProcessor.prototype, 'transformToFragment', getParserDistortion('transformToFragment')],
      [XSLTProcessor.prototype, 'transformToDocument', getParserDistortion('transformToDocument')]
    );
  }

  for (const [proto, property, distortion] of sinks) {
    const descriptor = proto ? Object.getOwnPropertyDescriptor(proto, property) : undefined;
    if (descriptor?.value) {
      distortions.set(descriptor.value, distortion);
    }
    // getters are only distorted for response documents, other sinks only need their setter
    if (descriptor?.get && property.startsWith('response')) {
      distortions.set(descriptor.get, distortion);
    }
    if (descriptor?.set) {
      distortions.set(descriptor.set, distortion);
    }
  }
}

function distortCreateElement(distortions: DistortionMap) {
  function getCreateElementDistortion(attrOrMethod: string) {
    return function (originalMethod: unknown, meta: SandboxPluginMeta) {
      const pluginId = meta.id;
      return function createElementDistortion(this: Document, ...args: unknown[]) {
        if (!isFunction(originalMethod)) {
          return undefined;
        }
        // the check runs on the created element itself, which is inert until inserted
        const element = originalMethod.apply(this, args);
        const nodeName = isElementNode(element) ? getElementLocalName(element) : '';
        if (forbiddenElements.includes(nodeName)) {
          logWarning(`Plugin ${pluginId} tried to create ${nodeName}`, {
            pluginId,
            attrOrMethod,
            param: nodeName,
            entity: 'document',
          });
          return document.createDocumentFragment();
        }
        return element;
      };
    };
  }
  for (const method of ['createElement', 'createElementNS']) {
    const descriptor = Object.getOwnPropertyDescriptor(Document.prototype, method);
    if (descriptor?.value) {
      distortions.set(descriptor.value, getCreateElementDistortion(method));
    }
  }
}

// if the node is a script, load it into the sandbox
// this allows webpack chunks to be loaded into the sandbox
// loadScriptIntoSandbox has restrictions on what scripts can be loaded
function loadScriptNodeIntoSandbox(script: HTMLScriptElement, sandboxEnv: SandboxEnvironment) {
  loadScriptIntoSandbox(script.src, sandboxEnv)
    .then(() => {
      script.onload?.call(script, new Event('load'));
    })
    .catch((err) => {
      script.onerror?.call(script, new ErrorEvent('error', { error: err }));
    });
}

// the whole subtree is checked because a forbidden element can be nested in a fragment or parent element
function isForbiddenInsertedNode(node: unknown, pluginId: string, attrOrMethod: string): boolean {
  if (!isNode(node)) {
    // not a node: the browser inserts it as text or rejects it
    return false;
  }
  const forbiddenElement = findForbiddenInsertedElement(node);
  if (forbiddenElement) {
    logWarning(`Plugin ${pluginId} tried to insert ${forbiddenElement}`, {
      pluginId,
      attrOrMethod,
      param: forbiddenElement,
      entity: 'HTMLElement',
    });
    return true;
  }
  return false;
}

function distortInsert(distortions: DistortionMap) {
  // methods that insert the single node found at `nodeArgIndex`
  function getInsertNodeDistortion(attrOrMethod: string, nodeArgIndex: number) {
    return function (originalMethod: unknown, meta: SandboxPluginMeta, sandboxEnv?: SandboxEnvironment) {
      const pluginId = meta.id;
      return function insertNodeDistortion(this: unknown, ...args: unknown[]) {
        const node = args[nodeArgIndex];
        if (isHTMLScriptElement(node)) {
          if (sandboxEnv) {
            loadScriptNodeIntoSandbox(node, sandboxEnv);
          }
          return attrOrMethod === 'appendChild' ? undefined : node;
        }
        if (isForbiddenInsertedNode(node, pluginId, attrOrMethod)) {
          return document.createDocumentFragment();
        }
        if (isFunction(originalMethod)) {
          return originalMethod.apply(this, args);
        }
      };
    };
  }

  // methods that insert any number of nodes or strings https://developer.mozilla.org/en-US/docs/Web/API/Element/append
  function getInsertNodesDistortion(attrOrMethod: string) {
    return function (originalMethod: unknown, meta: SandboxPluginMeta, sandboxEnv?: SandboxEnvironment) {
      const pluginId = meta.id;
      return function insertNodesDistortion(this: unknown, ...args: unknown[]) {
        const acceptedNodes: unknown[] = [];
        for (const node of args) {
          if (isHTMLScriptElement(node)) {
            if (sandboxEnv) {
              loadScriptNodeIntoSandbox(node, sandboxEnv);
            }
          } else if (!isForbiddenInsertedNode(node, pluginId, attrOrMethod)) {
            acceptedNodes.push(node);
          }
        }
        if (isFunction(originalMethod)) {
          originalMethod.apply(this, acceptedNodes);
        }
        return undefined;
      };
    };
  }

  const protoOf = (ctor: { prototype: object } | undefined) => ctor?.prototype;
  const singleNodeMethods: Array<[object | undefined, string, number]> = [
    [Node.prototype, 'appendChild', 0],
    [Node.prototype, 'insertBefore', 0],
    [Node.prototype, 'replaceChild', 0],
    [Element.prototype, 'insertAdjacentElement', 1],
    [Element.prototype, 'moveBefore', 0],
    [Document.prototype, 'moveBefore', 0],
    [DocumentFragment.prototype, 'moveBefore', 0],
    [Range.prototype, 'insertNode', 0],
    [Range.prototype, 'surroundContents', 0],
    [Document.prototype, 'body', 0],
    [protoOf(globalThis.HTMLTableElement), 'caption', 0],
    [protoOf(globalThis.HTMLTableElement), 'tHead', 0],
    [protoOf(globalThis.HTMLTableElement), 'tFoot', 0],
    [protoOf(globalThis.HTMLSelectElement), 'add', 0],
    [protoOf(globalThis.HTMLOptionsCollection), 'add', 0],
  ];
  for (const [proto, method, nodeArgIndex] of singleNodeMethods) {
    const descriptor = proto ? Object.getOwnPropertyDescriptor(proto, method) : undefined;
    if (descriptor?.value) {
      distortions.set(descriptor.value, getInsertNodeDistortion(method, nodeArgIndex));
    }
    if (descriptor?.set) {
      distortions.set(descriptor.set, getInsertNodeDistortion(method, nodeArgIndex));
    }
  }

  const multiNodeProtos = [
    Element.prototype,
    Document.prototype,
    DocumentFragment.prototype,
    CharacterData.prototype,
    DocumentType.prototype,
  ];
  for (const proto of multiNodeProtos) {
    for (const method of ['append', 'prepend', 'after', 'before', 'replaceWith', 'replaceChildren']) {
      const descriptor = Object.getOwnPropertyDescriptor(proto, method);
      if (descriptor?.value) {
        distortions.set(descriptor.value, getInsertNodesDistortion(method));
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
