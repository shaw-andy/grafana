import { setupMockedResourcesAPI } from './mocks/ResourcesAPI';
import { type VariableQuery, VariableQueryType } from './types';
import { CloudWatchVariableSupport } from './variables';

const logGroupsQuery: VariableQuery = {
  queryType: VariableQueryType.LogGroups,
  namespace: 'AWS/Logs',
  region: 'us-east-1',
  metricName: '',
  dimensionKey: '',
  instanceID: '',
  attributeName: '',
  resourceType: '',
  refId: 'A',
  logGroupPrefix: 'app',
  accountId: '123456789012',
};

describe('CloudWatch log group variable', () => {
  it('requests one page from the log-groups resource', async () => {
    const { api, fetchMock } = setupMockedResourcesAPI({
      response: [
        {
          value: {
            arn: 'arn:aws:logs:us-east-1:111111111111:log-group:app',
            name: 'app',
          },
          accountId: '123456789012',
        },
      ],
    });
    const variables = new CloudWatchVariableSupport(api);

    const result = await variables.execute(logGroupsQuery);

    expect(result).toEqual([
      {
        text: 'app',
        value: 'arn:aws:logs:us-east-1:111111111111:log-group:app',
        expandable: true,
      },
    ]);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const request = fetchMock.mock.calls[0][0];
    expect(request.url).toBe('/api/datasources/uid//resources/log-groups');
    expect(request.method).toBe('GET');
    expect(request.params).toMatchObject({
      region: 'us-east-1',
      accountId: '123456789012',
      logGroupNamePrefix: 'app',
      listAllLogGroups: 'false',
    });
  });
});
