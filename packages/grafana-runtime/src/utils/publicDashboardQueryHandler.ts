import { catchError, type Observable, of, switchMap, throwError } from 'rxjs';

import { type DataQuery, type DataQueryRequest, type DataQueryResponse } from '@grafana/data';

import { config } from '../config';
import { getBackendSrv } from '../services/backendSrv';

import { getPublicDashboardApiUrl } from './publicDashboardAccessToken';
import { type BackendDataSourceResponse, toDataQueryResponse } from './queryResponse';

export function publicDashboardQueryHandler(request: DataQueryRequest<DataQuery>): Observable<DataQueryResponse> {
  const {
    intervalMs,
    maxDataPoints,
    requestId,
    panelId,
    queryCachingTTL,
    range: { from: fromRange, to: toRange },
  } = request;
  // Return early if no queries exist
  if (!request.targets.length) {
    return of({ data: [] });
  }

  if (panelId == null || Number.isNaN(panelId)) {
    return of({ data: [] });
  }

  let url: string;
  try {
    url = getPublicDashboardApiUrl(config.publicDashboardAccessToken, `/panels/${panelId}/query`);
  } catch (err) {
    return throwError(() => err);
  }

  const body = {
    intervalMs,
    maxDataPoints,
    queryCachingTTL,
    timeRange: {
      from: fromRange.valueOf().toString(),
      to: toRange.valueOf().toString(),
      timezone: request.timezone,
    },
  };

  return getBackendSrv()
    .fetch<BackendDataSourceResponse>({
      url,
      method: 'POST',
      data: body,
      requestId,
    })
    .pipe(
      switchMap((raw) => {
        return of(toDataQueryResponse(raw, request.targets));
      }),
      catchError((err) => {
        return of(toDataQueryResponse(err));
      })
    );
}
