import { encodeUrl, getLogsEndpoint, type AwsUrl } from './aws_url';
import { expectSafeConsoleHref, hostileRegions } from './utils/consoleLinkSafety.test-utils';

describe('getEndpoint', () => {
  it('should return the default url for normal regions', () => {
    const result = getLogsEndpoint('us-east-1');
    expect(result).toBe('us-east-1.console.aws.amazon.com');
  });

  it('should return the us-gov url for us-gov regions', () => {
    const result = getLogsEndpoint('us-gov-east-1');
    expect(result).toBe('us-gov-east-1.console.amazonaws-us-gov.com');
  });

  it('should return the china url for cn regions', () => {
    const result = getLogsEndpoint('cn-northwest-1');
    expect(result).toBe('cn-northwest-1.console.amazonaws.cn');
  });
});

describe('encodeUrl console host', () => {
  const query: AwsUrl = {
    end: '2016-12-31T16:00:00.000Z',
    start: '2016-12-31T15:00:00.000Z',
    timeType: 'ABSOLUTE',
    tz: 'UTC',
    editorString: 'fields @timestamp | filter secretlogtext',
    isLiveTail: false,
    source: ['secretloggroup'],
  };

  it.each(['us-east-1', 'us-gov-east-1', 'cn-northwest-1'])(
    'keeps a single-label region on its partition console host (%s)',
    (region) => {
      const href = encodeUrl(query, region);
      expectSafeConsoleHref(href, 'secretloggroup');
      expect(new URL(href).hostname.startsWith(`${region}.`)).toBe(true);
    }
  );

  it.each(hostileRegions)('does not put the logs query on a host chosen by the region (%s)', (region) => {
    expectSafeConsoleHref(encodeUrl(query, region), 'secretloggroup');
  });
});
