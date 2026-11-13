import { type DataQuery, type DataSourceRef, getNextRefId } from '@grafana/data';

// This function checks if the query has defined properties beyond those defined in the DataQuery interface.
export function queryIsEmpty(query: DataQuery): boolean {
  const dataQueryProps = ['refId', 'hide', 'key', 'queryType', 'datasource'];

  for (const key in query) {
    // label is not a DataQuery prop, but it's defined in the query when called from the QueryRunner.
    if (key === 'label') {
      continue;
    }
    if (!dataQueryProps.includes(key)) {
      return false;
    }
  }

  return true;
}

export function addQuery(queries: DataQuery[], query?: Partial<DataQuery>, datasource?: DataSourceRef): DataQuery[] {
  const q: DataQuery = {
    ...query,
    refId: getNextRefId(queries),
    hide: false,
  };

  if (!q.datasource && datasource) {
    q.datasource = datasource;
  }

  return [...queries, q];
}

export function isDataQuery(url: string): boolean {
  if (url.indexOf('api/datasources/proxy') !== -1 || url.indexOf('api/ds/query') !== -1) {
    return true;
  }

  return false;
}

/**
 * Returns true when the URL resolves to the origin Grafana is served from.
 *
 * Requests to local URLs carry the viewer's org and device identifiers, so the decision has to be
 * made the same way the browser resolves the URL: scheme casing, leading whitespace, protocol-relative
 * URLs and backslashes must not make an external host look local.
 */
export function isLocalUrl(url: string) {
  try {
    return new URL(url, document.baseURI).origin === window.location.origin;
  } catch {
    return false;
  }
}

/**
 * Returns the input value for non empty string and undefined otherwise
 *
 * It is inadvisable to set a query param to an empty string as it will be added to the URL.
 * It is better to keep it undefined so the param won't be added to the URL at all.
 */
export function getQueryParamValue(value: string | undefined | null): string | undefined {
  return value || undefined;
}
