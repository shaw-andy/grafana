import {
  FieldType,
  type GrafanaConfig,
  getDefaultTimeRange,
  LoadingState,
  locationUtil,
  type PanelData,
  toDataFrame,
  type DataSourceInstanceSettings,
} from '@grafana/data';
import { type CorrelationData } from '@grafana/runtime';
import { type DataQuery } from '@grafana/schema';
import { updateConfig } from 'app/core/config';

import { LinkSrv, setLinkSrv } from '../../panel/panellinks/link_srv';
import { decorateWithCorrelations } from './decorators';
import { getFieldLinksForExplore } from './links';

const source = {
  uid: 'loki-uid',
  name: 'Loki',
  type: 'loki',
  meta: { id: 'loki' },
} as DataSourceInstanceSettings;

function sessionChanging(href: string, appSubUrl = ''): boolean {
  let url: URL;
  try {
    url = new URL(href, window.location.origin);
  } catch {
    return false;
  }
  if (url.origin !== window.location.origin) {
    return false;
  }
  let path = url.pathname;
  if (appSubUrl !== '' && (path === appSubUrl || path.startsWith(`${appSubUrl}/`))) {
    path = path.slice(appSubUrl.length) || '/';
  }
  path = path.replace(/\/+$/, '') || '/';
  return path === '/logout' || path.startsWith('/profile/switch-org/');
}

function linksFor(target: string, appSubUrl = '') {
  locationUtil.initialize({
    config: { appSubUrl } as GrafanaConfig,
    getVariablesUrlParams: jest.fn(),
    getTimeRangeForUrl: jest.fn(),
  });
  updateConfig({ disableSanitizeHtml: false });
  setLinkSrv(new LinkSrv());

  const frame = toDataFrame({
    refId: 'A',
    fields: [{ name: 'message', type: FieldType.string, values: ['hello'] }],
  });
  const correlation: CorrelationData = {
    uid: 'corr-1',
    label: 'View documentation',
    source,
    type: 'external',
    provisioned: false,
    config: { field: 'message', target: { url: target } },
  };
  const queries: DataQuery[] = [{ refId: 'A', datasource: { uid: source.uid, type: source.type } }];
  const panelData: PanelData = {
    series: [frame],
    state: LoadingState.Done,
    timeRange: getDefaultTimeRange(),
  };
  const decorated = decorateWithCorrelations({
    showCorrelationEditorLinks: false,
    queries,
    correlations: [correlation],
  })(panelData);
  const field = decorated.series[0].fields[0];
  return getFieldLinksForExplore({
    field,
    rowIndex: 0,
    range: panelData.timeRange,
    dataFrame: decorated.series[0],
  });
}

describe('external correlation links in Explore', () => {
  it.each(['/logout', '/logout?redirect=/login', '/profile/switch-org/2'])(
    'does not follow a stored session path %s',
    (target) => {
      const links = linksFor(target);
      expect(links.filter((link) => sessionChanging(link.href))).toEqual([]);
    }
  );

  it('does not follow a stored session path when the app is served under a subpath', () => {
    const links = linksFor('/logout', '/grafana');
    expect(links.filter((link) => sessionChanging(link.href, '/grafana'))).toEqual([]);
  });

  it('does not follow a stored absolute session url on this origin', () => {
    const links = linksFor(`${window.location.origin}/profile/switch-org/2`);
    expect(links.filter((link) => sessionChanging(link.href))).toEqual([]);
  });

  it('keeps an external documentation link and opens it in a new tab', () => {
    const links = linksFor('https://docs.example.com/guide');
    expect(links).toHaveLength(1);
    expect(links[0].href).toBe('https://docs.example.com/guide');
    expect(links[0].title).toBe('View documentation');
    expect(links[0].target).toBe('_blank');
    expect(sessionChanging(links[0].href)).toBe(false);
  });
});
