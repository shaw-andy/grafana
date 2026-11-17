import { createApi } from '@reduxjs/toolkit/query/react';

import { getAPIBaseURL } from '@grafana/api-clients';
import { createBaseQuery } from '@grafana/api-clients/rtkq';

const API_GROUP = 'scope.grafana.app' as const;
const API_VERSION = 'v0alpha1' as const;
const BASE_URL = getAPIBaseURL(API_GROUP, API_VERSION);

const baseQuery = createBaseQuery({
  baseURL: BASE_URL,
});

// Scope and scope node names are read from the page URL (`scopes`, `scope_node`), and endpoints.gen.ts is
// regenerated from Enterprise, so refuse any request path that could resolve outside the scope API.
const validatedBaseQuery: typeof baseQuery = (args, api, extraOptions) =>
  baseQuery({ ...args, validatePath: true }, api, extraOptions);

export const api = createApi({
  reducerPath: 'scopeAPIv0alpha1',
  baseQuery: validatedBaseQuery,
  endpoints: () => ({}),
});
