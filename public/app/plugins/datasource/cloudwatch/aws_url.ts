const JSURL = require('jsurl');

export interface AwsUrl {
  end: string;
  start: string;
  timeType?: 'ABSOLUTE' | 'RELATIVE';
  tz?: 'local' | 'UTC';
  unit?: string;
  editorString: string;
  isLiveTail: boolean;
  source: string[];
}

const defaultURL = 'console.aws.amazon.com';
const usGovURL = 'console.amazonaws-us-gov.com';
const chinaURL = 'console.amazonaws.cn';

// The region becomes the leftmost label of the console host, so anything other than a
// single DNS label would let it change which host the link points to.
const consoleRegionLabel = /^[a-z0-9]+(-[a-z0-9]+)*$/;

export function isConsoleRegion(region: string): boolean {
  return region.length <= 63 && consoleRegionLabel.test(region);
}

export function getLogsEndpoint(region: string): string {
  let url = defaultURL;
  if (region.startsWith('us-gov-')) {
    url = usGovURL;
  }
  if (region.startsWith('cn-')) {
    url = chinaURL;
  }
  return `${region}.${url}`;
}

function buildConsoleUrl(region: string, path: string, fragment: string): string {
  if (!isConsoleRegion(region)) {
    return '';
  }
  const url = new URL(`https://${getLogsEndpoint(region)}`);
  url.pathname = path;
  url.searchParams.set('region', region);
  return `${url.toString()}#${fragment}`;
}

export function encodeUrl(obj: AwsUrl, region: string): string {
  return buildConsoleUrl(region, '/cloudwatch/home', `logs-insights:queryDetail=${JSURL.stringify(obj)}`);
}

export function getServiceQuotasUrl(region: string): string {
  return buildConsoleUrl(region, '/servicequotas/home', '!/services/monitoring/quotas/L-5E141212');
}
