export { BASE_URL, API_GROUP, API_VERSION } from './baseAPI';
import { generatedAPI as rawAPI } from './endpoints.gen';

export * from './endpoints.gen';
export type { ProvisioningResourceRef as ResourceRef } from './endpoints.gen';

const SEGMENT_ARGS = new Set(['name', 'uid', 'guid']);

/**
 * The generated endpoints splice these arguments into the URL unencoded. `path` is a repository file
 * path whose `/` separators are meant to reach the server, so each of its segments is encoded alone.
 */
function encodePathArgs<T>(queryArg: T): T {
  if (!queryArg || typeof queryArg !== 'object') {
    return queryArg;
  }

  const encoded: Record<string, string> = {};
  for (const [key, value] of Object.entries(queryArg)) {
    if (typeof value !== 'string') {
      continue;
    }
    if (SEGMENT_ARGS.has(key)) {
      encoded[key] = encodeURIComponent(value);
    } else if (key === 'path') {
      encoded[key] = value.split('/').map(encodeURIComponent).join('/');
    }
  }
  return Object.assign({}, queryArg, encoded);
}

function encodeQueryArgs<Arg, Result>(definition: { query?: (queryArg: Arg) => Result }) {
  const query = definition.query;
  if (query) {
    definition.query = (queryArg) => query(encodePathArgs(queryArg));
  }
}

export const generatedAPI = rawAPI.enhanceEndpoints({
  endpoints: Object.fromEntries(Object.keys(rawAPI.endpoints).map((name) => [name, encodeQueryArgs])),
});
