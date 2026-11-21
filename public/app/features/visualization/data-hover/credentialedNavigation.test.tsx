import { render, screen } from '@testing-library/react';
import Feature from 'ol/Feature';
import { Point } from 'ol/geom';
import { type ReactElement } from 'react';
import { MemoryRouter } from 'react-router-dom-v5-compat';

import {
  createDataFrame,
  createTheme,
  FieldType,
  getDisplayProcessor,
  getLinksSupplier,
  type DataFrame,
} from '@grafana/data';
import { type MapLayerState } from 'app/plugins/panel/geomap/types';
import { GeomapTooltip } from 'app/plugins/panel/geomap/GeomapTooltip';

import { DataHoverRows } from './DataHoverRows';
import { DataHoverView } from './DataHoverView';

const theme = createTheme();
const origin = window.location.origin;

const logoutUrl = `${origin}/logout`;
const logoutAndOrgUrl = `${origin}/logout?orgId=2`;
const orgQueryUrl = `${origin}/d/abc?orgId=2`;
const switchOrgUrl = `${origin}/profile/switch-org/2`;
const subpathLogoutUrl = `${origin}/grafana/logout`;
const externalUrl = 'https://example.com/docs';
const sameOriginDashboardUrl = `${origin}/d/abc`;

function displayedFrame(
  name: string,
  value: string,
  links?: { title: string; url: string; targetBlank?: boolean }[]
): DataFrame {
  const frame = createDataFrame({
    fields: [
      {
        name,
        type: FieldType.string,
        values: [value],
        config: links ? { links } : {},
      },
    ],
  });
  const field = frame.fields[0];
  field.display = getDisplayProcessor({ field, theme });
  if (links) {
    field.getLinks = getLinksSupplier(frame, field, {}, (next) => next ?? '');
  }
  return frame;
}

function markersFeature(frame: DataFrame, rowIndex = 0) {
  return new Feature({
    frame,
    rowIndex,
    geometry: new Point([0, 0]),
  });
}

function propertyFeature(properties: Record<string, string>) {
  return new Feature({
    geometry: new Point([1, 2]),
    ...properties,
  });
}

function layer(name: string, features: Feature[]) {
  return {
    layer: { getName: () => name } as MapLayerState,
    features,
  };
}

function renderInRouter(ui: ReactElement) {
  return render(<MemoryRouter future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>{ui}</MemoryRouter>);
}

function isSameOriginSessionAction(href: string): boolean {
  let url: URL;
  try {
    url = new URL(href, window.location.href);
  } catch {
    return false;
  }
  if (url.origin !== window.location.origin) {
    return false;
  }
  const path = url.pathname.replace(/\/+$/, '') || '/';
  if (path === '/logout' || path.endsWith('/logout')) {
    return true;
  }
  if (/\/profile\/switch-org\/[^/]+$/.test(path)) {
    return true;
  }
  return url.searchParams.has('orgId');
}

function sessionActionAnchors(): HTMLAnchorElement[] {
  return Array.from(document.querySelectorAll('a')).filter((anchor) => {
    const attribute = anchor.getAttribute('href') ?? '';
    return isSameOriginSessionAction(attribute) || isSameOriginSessionAction(anchor.href);
  });
}

function expectPlainText(value: string) {
  const node = screen.getByText(value);
  expect(node.closest('a')).toBeNull();
}

describe('credentialed navigation from hover values', () => {
  it('keeps a same-origin logout field value as text in the shared hover view', () => {
    renderInRouter(<DataHoverView data={displayedFrame('note', logoutUrl)} rowIndex={0} />);

    expectPlainText(logoutUrl);
    expect(sessionActionAnchors()).toEqual([]);
  });

  it.each([logoutAndOrgUrl, orgQueryUrl, switchOrgUrl, subpathLogoutUrl])(
    'does not navigate to the session action %s from a displayed field',
    (url) => {
      renderInRouter(<DataHoverView data={displayedFrame('note', url)} rowIndex={0} />);

      expectPlainText(url);
      expect(sessionActionAnchors()).toEqual([]);
    }
  );

  it('keeps an external http address as text when it is only a field value', () => {
    renderInRouter(<DataHoverView data={displayedFrame('note', externalUrl)} rowIndex={0} />);

    expectPlainText(externalUrl);
    expect(screen.queryByRole('link')).not.toBeInTheDocument();
  });

  it('keeps a javascript address as text', () => {
    const value = 'javascript:alert(1)';
    renderInRouter(<DataHoverView data={displayedFrame('note', value)} rowIndex={0} />);

    expectPlainText(value);
    expect(document.querySelector('a[href^="javascript:"]')).toBeNull();
  });

  it('still follows an explicit data link that does not change the session', () => {
    renderInRouter(
      <DataHoverView
        data={displayedFrame('note', 'steady', [
          { title: 'Dashboard', url: sameOriginDashboardUrl, targetBlank: false },
          { title: 'Docs', url: externalUrl, targetBlank: true },
        ])}
        rowIndex={0}
      />
    );

    expect(screen.getByRole('link', { name: 'Dashboard' })).toHaveAttribute('href', '/d/abc');
    expect(screen.getByRole('link', { name: /Docs/ })).toHaveAttribute('href', externalUrl);
    expect(sessionActionAnchors()).toEqual([]);
  });

  it.each([
    ['logout', logoutUrl],
    ['organization query', orgQueryUrl],
    ['organization switch', switchOrgUrl],
  ])('does not follow an explicit data link to a %s address', (_label, url) => {
    renderInRouter(
      <DataHoverView
        data={displayedFrame('note', 'steady', [
          { title: 'Open', url, targetBlank: true },
          { title: 'Stay', url, targetBlank: false },
        ])}
        rowIndex={0}
      />
    );

    expect(sessionActionAnchors()).toEqual([]);
  });

  it('renders a geomap marker frame through the clickable tooltip without a session link', () => {
    const frame = displayedFrame('note', logoutUrl, [{ title: 'Docs', url: externalUrl, targetBlank: true }]);
    renderInRouter(
      <GeomapTooltip
        isOpen={false}
        onClose={jest.fn()}
        ttip={{
          pageX: 12,
          pageY: 24,
          point: { lat: 0, lon: 0 },
          layers: [layer('Markers', [markersFeature(frame)])],
        }}
      />
    );

    expectPlainText(logoutUrl);
    expect(sessionActionAnchors()).toEqual([]);

    const docs = screen.getByRole('link', { name: /Docs/ });
    expect(docs).toHaveAttribute('href', externalUrl);
    let element: HTMLElement | null = docs;
    while (element) {
      expect(window.getComputedStyle(element).pointerEvents).not.toBe('none');
      element = element.parentElement;
    }
  });

  it('renders geojson properties that are not attached to a frame as text', () => {
    renderInRouter(
      <GeomapTooltip
        isOpen={false}
        onClose={jest.fn()}
        ttip={{
          pageX: 12,
          pageY: 24,
          point: { lat: 1, lon: 2 },
          layers: [layer('GeoJSON', [propertyFeature({ note: orgQueryUrl })])],
        }}
      />
    );

    expectPlainText(orgQueryUrl);
    expect(sessionActionAnchors()).toEqual([]);
  });

  it('does not turn a multi-feature collapse label into a session link', () => {
    const frame = displayedFrame('note', switchOrgUrl);
    renderInRouter(
      <DataHoverRows
        activeTabIndex={0}
        layers={[layer('Markers', [markersFeature(frame, 0), markersFeature(frame, 0)])]}
      />
    );

    expect(screen.getAllByText(switchOrgUrl).length).toBeGreaterThan(0);
    expect(sessionActionAnchors()).toEqual([]);
  });
});
