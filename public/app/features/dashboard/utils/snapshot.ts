type UnknownRecord = Record<string, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Snapshots are shared with anyone who has the link, so a canvas element must not carry a request that would be
 * sent with the viewer's session when they click it. Returns a copy; the input is not modified.
 */
export function removeRequestsFromPanelOptions<T>(panelType: string | undefined, options: T): T {
  if (panelType !== 'canvas' || !isRecord(options) || !isRecord(options.root)) {
    return options;
  }

  return { ...options, root: removeRequestsFromCanvasElement(options.root) };
}

function removeRequestsFromCanvasElement(element: UnknownRecord): UnknownRecord {
  const { links, actions, config, elements, ...rest } = element;
  const result: UnknownRecord = rest;

  if (isRecord(config)) {
    const { api, ...configWithoutApi } = config;
    result.config = configWithoutApi;
  } else if (config !== undefined) {
    result.config = config;
  }

  if (Array.isArray(elements)) {
    result.elements = elements.map((child) => (isRecord(child) ? removeRequestsFromCanvasElement(child) : child));
  } else if (elements !== undefined) {
    result.elements = elements;
  }

  return result;
}
