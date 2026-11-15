import { render, screen } from 'test/test-utils';

import { catalogThumbnailViolation } from '../assertCatalogThumbnail';
import { createMockGnetDashboard } from '../utils/test-utils';

import { DashboardResultsGrid } from './DashboardResultsGrid';

jest.mock('@grafana/assistant', () => ({
  useAssistant: () => ({ isAvailable: false, openAssistant: jest.fn() }),
  createAssistantContextItem: jest.fn((type: string, data: object) => ({ type, ...data })),
}));

const traversalHrefs = [
  ['parent segments', '/../../../logout'],
  ['relative parent segments', '../../../logout'],
  ['percent-encoded dot segments', '/%2e%2e/%2e%2e/%2e%2e/logout'],
  ['backslashes', '\\..\\..\\..\\logout'],
  ['scheme', 'https://evil.example/logout'],
  ['protocol-relative', '//evil.example/logout'],
] as const;

function renderGrid(items: Array<ReturnType<typeof createMockGnetDashboard>>) {
  return render(
    <DashboardResultsGrid
      provisionedSlice={[]}
      communitySlice={items}
      currentPage={1}
      datasourceType="prometheus"
      datasourceUid="prom"
      isCompatibilityAppEnabled={false}
      compatibilityMap={new Map()}
      onClickProvisionedDashboard={jest.fn()}
      onClickCommunityDashboard={jest.fn()}
      onCheckCompatibility={jest.fn()}
    />
  );
}

describe('DashboardResultsGrid community thumbnails', () => {
  it('puts a grafana.com screenshot path on the card image', () => {
    renderGrid([
      createMockGnetDashboard({
        id: 1860,
        name: 'Node Exporter',
        screenshots: [{ links: [{ rel: 'image', href: '/api/dashboards/1860/images/2' }] }],
      }),
    ]);

    const image = screen.getByRole('img', { name: 'Node Exporter' });
    expect(image).toHaveAttribute('src', '/api/gnet/api/dashboards/1860/images/2');
    expect(catalogThumbnailViolation(image.getAttribute('src'))).toBeNull();
  });

  it('does not put a screenshot href that resolves outside the gnet proxy on the card image', () => {
    renderGrid(
      traversalHrefs.map(([name, href], index) =>
        createMockGnetDashboard({
          id: index + 1,
          name,
          screenshots: [{ links: [{ rel: 'image', href }] }],
        })
      )
    );

    expect(
      traversalHrefs.map(([name]) => [
        name,
        catalogThumbnailViolation(screen.queryByRole('img', { name })?.getAttribute('src')),
      ])
    ).toEqual(traversalHrefs.map(([name]) => [name, null]));
  });
});
