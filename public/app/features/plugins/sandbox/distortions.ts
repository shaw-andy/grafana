import { type ProxyTarget } from '@locker/near-membrane-shared';
import DOMPurify from 'dompurify';
import { cloneDeep, isFunction } from 'lodash';

import { type Monaco } from '@grafana/ui';

import { loadScriptIntoSandbox } from './codeLoader';
import { forbiddenElements, forbiddenInsertedElements } from './constants';
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

// Plugins can pass objects whose toString returns a different value on every call, so markup is converted
// to a string once and that same string is both checked and handed to the browser.
function toMarkupString(value: unknown): unknown {
  if (window.trustedTypes?.isHTML(value)) {
    return value;
  }
  return value === null ? '' : String(value);
}

function distortInnerHTML(distortions: DistortionMap) {
  function getMarkupDistortion(markupIndex: number) {
    return function getInnerHTMLDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
      const pluginId = meta.id;
      return function innerHTMLDistortion(this: HTMLElement, ...args: unknown[]) {
        if (markupIndex < args.length) {
          const markup = toMarkupString(args[markupIndex]);
          args[markupIndex] = markup;
          // NOTE: DOMPurify anti-tamper mechanism requires us to clone the string
          // calling any method whatsoever on a string will cause the string to be tampered
          // and DOMPurify will return empty strings
          const lowerCase = String(markup).toLowerCase();
          for (const forbiddenElement of forbiddenInsertedElements) {
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
              param: String(markup),
              entity: 'HTMLElement',
            });
            args[markupIndex] = DOMPurify.sanitize(String(markup));
          }
        }

        if (isFunction(originalMethod)) {
          return originalMethod.apply(this, args);
        }
      };
    };
  }

  const markupSinks: Array<[PropertyDescriptor | undefined, number]> = [
    [Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML'), 0],
    [Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML'), 0],
    [Object.getOwnPropertyDescriptor(Element.prototype, 'insertAdjacentHTML'), 1],
    [Object.getOwnPropertyDescriptor(Element.prototype, 'setHTMLUnsafe'), 0],
    [Object.getOwnPropertyDescriptor(ShadowRoot.prototype, 'innerHTML'), 0],
    [Object.getOwnPropertyDescriptor(ShadowRoot.prototype, 'setHTMLUnsafe'), 0],
    [Object.getOwnPropertyDescriptor(DOMParser.prototype, 'parseFromString'), 0],
    [Object.getOwnPropertyDescriptor(Document, 'parseHTMLUnsafe'), 0],
    [Object.getOwnPropertyDescriptor(Range.prototype, 'createContextualFragment'), 0],
  ];

  for (const [descriptor, markupIndex] of markupSinks) {
    if (descriptor?.set) {
      distortions.set(descriptor.set, getMarkupDistortion(markupIndex));
    }
    if (descriptor?.value) {
      distortions.set(descriptor.value, getMarkupDistortion(markupIndex));
    }
  }
}

function distortCreateElement(distortions: DistortionMap) {
  function rejectCreation(pluginId: string, attrOrMethod: string, localName: string) {
    if (!forbiddenElements.includes(localName.toLowerCase())) {
      return false;
    }
    logWarning(`Plugin ${pluginId} tried to create ${localName}`, {
      pluginId,
      attrOrMethod,
      param: localName,
      entity: 'document',
    });
    return true;
  }

  function getCreateElementDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    const pluginId = meta.id;
    return function createElementDistortion(this: Document, arg?: unknown, options?: unknown) {
      const tagName = String(arg);
      if (rejectCreation(pluginId, 'createElement', tagName)) {
        return document.createDocumentFragment();
      }
      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, [tagName, options]);
      }
    };
  }

  function getCreateElementNSDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    const pluginId = meta.id;
    return function createElementNSDistortion(
      this: Document,
      namespace?: unknown,
      qualifiedName?: unknown,
      options?: unknown
    ) {
      const name = String(qualifiedName);
      const localName = name.slice(name.indexOf(':') + 1);
      if (rejectCreation(pluginId, 'createElementNS', localName)) {
        return document.createDocumentFragment();
      }
      if (isFunction(originalMethod)) {
        return originalMethod.apply(this, [namespace, name, options]);
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

const nodeTypeGetter = Object.getOwnPropertyDescriptor(Node.prototype, 'nodeType')?.get;
const localNameGetter = Object.getOwnPropertyDescriptor(Element.prototype, 'localName')?.get;
const elementQuerySelector = Element.prototype.querySelector;
const fragmentQuerySelector = DocumentFragment.prototype.querySelector;
const forbiddenInsertedElementsSelector = forbiddenInsertedElements.join(',');

function getLocalName(element: unknown): string {
  return String(Reflect.apply(localNameGetter!, element, [])).toLowerCase();
}

/**
 * Returns the forbidden element that inserting `node` would put into a document, if any.
 *
 * Elements and fragments are searched as a whole because parsed markup (e.g. createContextualFragment)
 * can hold scripts that run once the subtree is connected. Native getters are used so the node's
 * internal type decides, not properties the plugin can shadow.
 */
function findForbiddenInsertedElement(node: unknown): string | undefined {
  let nodeType: number;
  try {
    nodeType = Reflect.apply(nodeTypeGetter!, node, []);
  } catch (e) {
    // not a DOM node: strings and other values are inserted as text
    return undefined;
  }

  let found: Element | null = null;
  if (nodeType === Node.ELEMENT_NODE) {
    const localName = getLocalName(node);
    if (forbiddenInsertedElements.includes(localName)) {
      return localName;
    }
    found = Reflect.apply(elementQuerySelector, node, [forbiddenInsertedElementsSelector]);
  } else if (nodeType === Node.DOCUMENT_FRAGMENT_NODE) {
    found = Reflect.apply(fragmentQuerySelector, node, [forbiddenInsertedElementsSelector]);
  }
  return found ? getLocalName(found) : undefined;
}

function rejectInsertion(node: unknown, meta: SandboxPluginMeta, attrOrMethod: string): boolean {
  const forbiddenElement = findForbiddenInsertedElement(node);
  if (!forbiddenElement) {
    return false;
  }
  logWarning(`Plugin ${meta.id} tried to insert ${forbiddenElement}`, {
    pluginId: meta.id,
    attrOrMethod,
    param: forbiddenElement,
    entity: 'HTMLElement',
  });
  return true;
}

function distortInsert(distortions: DistortionMap) {
  function getInsertDistortion(nodeIndex: number, rejectedResult: () => unknown) {
    return function getDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
      const attrOrMethod = isFunction(originalMethod) ? originalMethod.name : 'insert';
      return function insertDistortion(this: Node, ...args: unknown[]) {
        if (rejectInsertion(args[nodeIndex], meta, attrOrMethod)) {
          return rejectedResult();
        }
        if (isFunction(originalMethod)) {
          return originalMethod.apply(this, args);
        }
      };
    };
  }

  const returnsFragment = () => document.createDocumentFragment();
  const returnsUndefined = () => undefined;

  const nodeFirst = getInsertDistortion(0, returnsFragment);
  const descriptors = [
    Object.getOwnPropertyDescriptor(Node.prototype, 'insertBefore'),
    Object.getOwnPropertyDescriptor(Node.prototype, 'replaceChild'),
    Object.getOwnPropertyDescriptor(Element.prototype, 'moveBefore'),
    Object.getOwnPropertyDescriptor(Document.prototype, 'moveBefore'),
    Object.getOwnPropertyDescriptor(DocumentFragment.prototype, 'moveBefore'),
  ];
  for (const descriptor of descriptors) {
    if (descriptor?.value) {
      distortions.set(descriptor.value, nodeFirst);
    }
  }

  const descriptorAdjacent = Object.getOwnPropertyDescriptor(Element.prototype, 'insertAdjacentElement');
  if (descriptorAdjacent?.value) {
    distortions.set(descriptorAdjacent.value, getInsertDistortion(1, returnsFragment));
  }

  const rangeDescriptors = [
    Object.getOwnPropertyDescriptor(Range.prototype, 'insertNode'),
    Object.getOwnPropertyDescriptor(Range.prototype, 'surroundContents'),
  ];
  for (const descriptor of rangeDescriptors) {
    if (descriptor?.value) {
      distortions.set(descriptor.value, getInsertDistortion(0, returnsUndefined));
    }
  }
}

// set distortions to append elements to the document
function distortAppend(distortions: DistortionMap) {
  // append accepts an array of nodes to append https://developer.mozilla.org/en-US/docs/Web/API/Node/append
  function getAppendDistortion(originalMethod: unknown, meta: SandboxPluginMeta) {
    const attrOrMethod = isFunction(originalMethod) ? originalMethod.name : 'append';
    return function appendDistortion(this: Node, ...args: unknown[]) {
      const acceptedNodes = args.filter((node) => !rejectInsertion(node, meta, attrOrMethod));

      if (isFunction(originalMethod)) {
        originalMethod.apply(this, acceptedNodes);
      }
      // https://developer.mozilla.org/en-US/docs/Web/API/Element/append#return_value
      return undefined;
    };
  }

  // appendChild accepts a single node to add https://developer.mozilla.org/en-US/docs/Web/API/Node/appendChild
  function getAppendChildDistortion(originalMethod: unknown, meta: SandboxPluginMeta, sandboxEnv?: SandboxEnvironment) {
    return function appendChildDistortion(this: Node, arg?: Node) {
      // if the node is a script, load it into the sandbox instead of the document
      // this allows webpack chunks to be loaded into the sandbox
      // loadScriptIntoSandbox has restrictions on what scripts can be loaded
      if (sandboxEnv && arg instanceof HTMLScriptElement) {
        loadScriptIntoSandbox(arg.src, sandboxEnv)
          .then(() => {
            arg.onload?.call(arg, new Event('load'));
          })
          .catch((err) => {
            arg.onerror?.call(arg, new ErrorEvent('error', { error: err }));
          });
        return undefined;
      }
      if (rejectInsertion(arg, meta, 'appendChild')) {
        return document.createDocumentFragment();
      }
      if (isFunction(originalMethod)) {
        return originalMethod.call(this, arg);
      }
    };
  }

  const prototypes = [
    Element.prototype,
    Document.prototype,
    DocumentFragment.prototype,
    CharacterData.prototype,
    DocumentType.prototype,
  ];
  const methods = ['append', 'prepend', 'replaceChildren', 'after', 'before', 'replaceWith'];

  for (const prototype of prototypes) {
    for (const method of methods) {
      const descriptor = Object.getOwnPropertyDescriptor(prototype, method);
      if (descriptor?.value) {
        distortions.set(descriptor.value, getAppendDistortion);
      }
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
