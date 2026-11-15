import { http, HttpResponse } from 'msw';
import { of } from 'rxjs';
import { render, screen } from 'test/test-utils';

import { type DataSourceInstanceListItem } from '@grafana/data';
import { config, setBackendSrv } from '@grafana/runtime';
import { useDataSourceInstanceList } from '@grafana/runtime/unstable';
import server, { setupMockServer } from '@grafana/test-utils/server';
import { backendSrv } from 'app/core/services/backend_srv';

import { TemplateDashboardModal } from './TemplateDashboardModal';
import { catalogThumbnailViolation } from './assertCatalogThumbnail';

jest.mock('@grafana/assistant', () => ({
  useAssistant: () => ({ isAvailable: false, openAssistant: jest.fn() }),
  createAssistantContextItem: jest.fn((type: string, data: object) => ({ type, ...data })),
  isAssistantAvailable: jest.fn(() => of(false)),
}));

setBackendSrv(backendSrv);
setupMockServer();

const testDataSource = {
  name: 'Test Data Source',
  uid: 'test-data-source-uid',
  type: 'grafana-testdata-datasource',
} as DataSourceInstanceListItem;

jest.mock('@grafana/runtime/unstable', () => ({
  ...jest.requireActual('@grafana/runtime/unstable'),
  useDataSourceInstanceList: jest.fn(() => ({ isLoading: false, items: [] })),
}));

const mockUseDataSourceInstanceList = jest.mocked(useDataSourceInstanceList);

function catalogItem(id: number, name: string, href: string) {
  return {
    id,
    name,
    description: 'template',
    slug: 'template',
    downloads: 1,
    datasource: 'grafana-testdata-datasource',
    screenshots: [{ links: [{ rel: 'image', href }] }],
  };
}

const traversalHrefs = [
  ['parent segments', '/../../../logout'],
  ['relative parent segments', '../../../logout'],
  ['percent-encoded dot segments', '/%2e%2e/%2e%2e/%2e%2e/logout'],
  ['backslashes', '\\..\\..\\..\\logout'],
  ['scheme', 'https://evil.example/logout'],
  ['protocol-relative', '//evil.example/logout'],
] as const;

describe('Grafana templates tab thumbnails', () => {
  let catalogRequestUrl = '';

  beforeEach(() => {
    catalogRequestUrl = '';
    config.featureToggles.dashboardTemplates = true;
    mockUseDataSourceInstanceList.mockReturnValue({ isLoading: false, items: [testDataSource] });
  });

  it('keeps a grafana.com screenshot path on the gnet proxy', async () => {
    server.use(
      http.get('/api/gnet/dashboards', ({ request }) => {
        catalogRequestUrl = request.url;
        return HttpResponse.json({
          page: 1,
          pages: 1,
          items: [catalogItem(1860, 'Node Exporter', '/api/dashboards/1860/images/2')],
        });
      })
    );

    render(<TemplateDashboardModal />, {
      historyOptions: { initialEntries: ['/dashboards?templateDashboards=true'] },
    });

    const image = await screen.findByRole('img', { name: 'Node Exporter' });
    const catalogUrl = new URL(catalogRequestUrl);
    expect(catalogUrl.pathname).toBe('/api/gnet/dashboards');
    expect(catalogUrl.searchParams.get('orgSlug')).toBe('raintank');
    expect(catalogUrl.searchParams.get('categorySlug')).toBe('templates');
    expect(catalogUrl.searchParams.get('includeScreenshots')).toBe('true');
    expect(image).toHaveAttribute('src', '/api/gnet/api/dashboards/1860/images/2');
    expect(catalogThumbnailViolation(image.getAttribute('src'))).toBeNull();
  });

  it('does not assign a screenshot href that the browser resolves outside the gnet proxy', async () => {
    server.use(
      http.get('/api/gnet/dashboards', ({ request }) => {
        catalogRequestUrl = request.url;
        return HttpResponse.json({
          page: 1,
          pages: 1,
          items: traversalHrefs.map(([name, href], index) => catalogItem(index + 1, name, href)),
        });
      })
    );

    render(<TemplateDashboardModal />, {
      historyOptions: { initialEntries: ['/dashboards?templateDashboards=true'] },
    });

    await screen.findByText('parent segments');
    expect(new URL(catalogRequestUrl).searchParams.get('orgSlug')).toBe('raintank');

    expect(
      traversalHrefs.map(([name]) => [
        name,
        catalogThumbnailViolation(screen.queryByRole('img', { name })?.getAttribute('src')),
      ])
    ).toEqual(traversalHrefs.map(([name]) => [name, null]));
  });

  it('keeps a query string that contains parent segments from changing the request path', async () => {
    server.use(
      http.get('/api/gnet/dashboards', () =>
        HttpResponse.json({
          page: 1,
          pages: 1,
          items: [catalogItem(3, 'Query only', '/api/dashboards/3/images/1?next=../logout')],
        })
      )
    );

    render(<TemplateDashboardModal />, {
      historyOptions: { initialEntries: ['/dashboards?templateDashboards=true'] },
    });

    const image = await screen.findByRole('img', { name: 'Query only' });
    expect(new URL(image.getAttribute('src') ?? '', 'http://grafana.local').pathname).toBe(
      '/api/gnet/api/dashboards/3/images/1'
    );
    expect(catalogThumbnailViolation(image.getAttribute('src'))).toBeNull();
  });
});
