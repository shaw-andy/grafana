// The graph is generated on the browser main thread for every viewer of a saved panel.
export const MAX_NODE_GRAPH_COUNT = 1000;

/**
 * Validates a node count from a saved query, which may come from hand-edited dashboard JSON.
 * Returns undefined when no count is set so the generator default applies.
 */
export function parseNodeGraphCount(count: unknown): number | undefined {
  if (count === undefined || count === null || count === '') {
    return undefined;
  }
  const value = Number(count);
  if (!Number.isFinite(value) || value < 1) {
    throw new Error(`Invalid node_graph count "${String(count)}": count must be a positive number`);
  }
  return Math.min(Math.floor(value), MAX_NODE_GRAPH_COUNT);
}

/**
 * Bounds a count typed into the query editor. Returns undefined for input that is not a number.
 */
export function clampNodeGraphCount(count: number): number | undefined {
  if (Number.isNaN(count)) {
    return undefined;
  }
  return Math.min(Math.max(Math.floor(count), 1), MAX_NODE_GRAPH_COUNT);
}
