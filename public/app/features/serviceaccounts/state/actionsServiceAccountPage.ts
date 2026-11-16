import { getBackendSrv, locationService } from '@grafana/runtime';
import { accessControlQueryParam } from 'app/core/utils/accessControl';
import { isSafeIdPathSegment } from 'app/core/utils/pathSegment';
import { type ServiceAccountDTO } from 'app/types/serviceaccount';
import { type ThunkResult } from 'app/types/store';

import { type ServiceAccountToken } from '../components/CreateTokenModal';

import {
  serviceAccountFetchBegin,
  serviceAccountFetchEnd,
  serviceAccountLoaded,
  serviceAccountTokensLoaded,
} from './reducers';

const BASE_URL = `/api/serviceaccounts`;
const pathOptions = { validatePath: true };

export function loadServiceAccount(saUid: string): ThunkResult<void> {
  return async (dispatch) => {
    if (!isSafeIdPathSegment(saUid)) {
      return;
    }
    dispatch(serviceAccountFetchBegin());
    try {
      const response = await getBackendSrv().get(
        `${BASE_URL}/${encodeURIComponent(saUid)}`,
        accessControlQueryParam(),
        undefined,
        pathOptions
      );
      dispatch(serviceAccountLoaded(response));
    } catch (error) {
      console.error(error);
    } finally {
      dispatch(serviceAccountFetchEnd());
    }
  };
}

export function updateServiceAccount(serviceAccount: ServiceAccountDTO): ThunkResult<void> {
  return async (dispatch) => {
    await getBackendSrv().patch(
      `${BASE_URL}/${encodeURIComponent(serviceAccount.uid)}?accesscontrol=true`,
      { ...serviceAccount },
      pathOptions
    );
    dispatch(loadServiceAccount(serviceAccount.uid));
  };
}

export function deleteServiceAccount(serviceAccountUid: string): ThunkResult<void> {
  return async () => {
    await getBackendSrv().delete(`${BASE_URL}/${encodeURIComponent(serviceAccountUid)}`, undefined, pathOptions);
    locationService.push('/org/serviceaccounts');
  };
}

export function createServiceAccountToken(
  saUid: string,
  token: ServiceAccountToken,
  onTokenCreated: (key: string) => void
): ThunkResult<void> {
  return async (dispatch) => {
    const result = await getBackendSrv().post(`${BASE_URL}/${encodeURIComponent(saUid)}/tokens`, token, pathOptions);
    onTokenCreated(result.key);
    dispatch(loadServiceAccountTokens(saUid));
  };
}

export function deleteServiceAccountToken(saUid: string, id: number): ThunkResult<void> {
  return async (dispatch) => {
    await getBackendSrv().delete(`${BASE_URL}/${encodeURIComponent(saUid)}/tokens/${id}`, undefined, pathOptions);
    dispatch(loadServiceAccountTokens(saUid));
  };
}

export function loadServiceAccountTokens(saUid: string): ThunkResult<void> {
  return async (dispatch) => {
    if (!isSafeIdPathSegment(saUid)) {
      return;
    }
    try {
      const response = await getBackendSrv().get(
        `${BASE_URL}/${encodeURIComponent(saUid)}/tokens`,
        undefined,
        undefined,
        pathOptions
      );
      dispatch(serviceAccountTokensLoaded(response));
    } catch (error) {
      console.error(error);
    }
  };
}
