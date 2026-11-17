import { type BackendSrvRequest, DataSourceWithBackend } from '@grafana/runtime';

import { type AzureMonitorQuery } from './types/query';
import { type AzureMonitorDataSourceJsonData } from './types/types';
import { assertResourcePathContained } from './utils/common';

export default class AzureDataSourceWithBackend extends DataSourceWithBackend<
  AzureMonitorQuery,
  AzureMonitorDataSourceJsonData
> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  async getResource<T = any>(
    path: string,
    params?: BackendSrvRequest['params'],
    options?: Partial<BackendSrvRequest>
  ): Promise<T> {
    return super.getResource<T>(assertResourcePathContained(path), params, options);
  }

  async postResource<T = unknown>(
    path: string,
    data?: BackendSrvRequest['data'],
    options?: Partial<BackendSrvRequest>
  ): Promise<T> {
    return super.postResource<T>(assertResourcePathContained(path), data, options);
  }
}
