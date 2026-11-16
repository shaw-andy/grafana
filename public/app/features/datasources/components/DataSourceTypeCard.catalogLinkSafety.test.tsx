import { render } from 'test/test-utils';

import { type DataSourcePluginMeta, PluginType } from '@grafana/data';
import { config } from '@grafana/runtime';

import { buildCategories } from '../state/buildCategories';

import { DataSourceTypeCard } from './DataSourceTypeCard';

/**
 * Same rule as the plugin catalog panel: a plugin info link must not be an
 * address the browser will request from this Grafana server, and it must not
 * be protocol-relative. The card appends a query string before LinkButton
 * sanitizes the href, so the assertion is on the rendered href.
 */
function isUnsafeCatalogHref(href: string | null): boolean {
  if (href == null) {
    return false;
  }

  const trimmed = href.trim();
  if (trimmed.startsWith('//')) {
    return true;
  }

  let url: URL;
  try {
    url = new URL(href, window.location.href);
  } catch {
    return true;
  }

  if (url.protocol === 'about:' && url.pathname === 'blank') {
    return false;
  }

  if (url.hostname.toLowerCase() === window.location.hostname.toLowerCase()) {
    return true;
  }

  return url.protocol !== 'http:' && url.protocol !== 'https:';
}

function unsafeHrefs(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll('a')).flatMap((anchor) => {
    const href = anchor.getAttribute('href');
    return isUnsafeCatalogHref(href) ? [href ?? ''] : [];
  });
}

function datasourceWithFirstLink(url: string): DataSourcePluginMeta {
  return {
    id: 'publisher-datasource',
    name: 'Publisher datasource',
    type: PluginType.datasource,
    module: 'publisher',
    baseUrl: '',
    info: {
      author: { name: 'Publisher' },
      description: 'External datasource',
      links: [
        { name: 'Docs', url },
        { name: 'Site', url: 'https://example.com/ds-site' },
      ],
      logos: { small: 'small', large: 'large' },
      screenshots: [],
    },
  };
}

function renderListedCard(url: string) {
  const plugin = datasourceWithFirstLink(url);
  const listed = buildCategories([plugin])
    .flatMap((category) => category.plugins)
    .find((item) => item.id === plugin.id);

  if (!listed) {
    throw new Error('datasource was not listed');
  }

  return render(<DataSourceTypeCard dataSourcePlugin={listed} onClick={() => undefined} />);
}

describe('DataSourceTypeCard plugin info links', () => {
  const previousAppUrl = config.appUrl;

  beforeEach(() => {
    config.appUrl = `${window.location.origin}/`;
    window.history.pushState({}, '', '/connections/datasources/new');
  });

  afterEach(() => {
    config.appUrl = previousAppUrl;
  });

  it('keeps an external https learn-more link and preserves the campaign query', () => {
    const { container } = renderListedCard('https://example.com/ds-docs');
    const href = container.querySelector('a')?.getAttribute('href');

    expect(unsafeHrefs(container)).toEqual([]);
    expect(href).toBe('https://example.com/ds-docs?utm_source=grafana_add_ds');
  });

  it.each([
    '/logout',
    '/profile/switch-org/2',
    `${window.location.origin}/logout`,
    `${window.location.origin}/profile/switch-org/2`,
    `//${window.location.host}/logout`,
    '//example.com/docs',
    '&#47;logout',
    ' /logout',
    '/\tlogout',
    '/%6Cogout',
    '../logout',
    `https://${window.location.hostname}/logout`,
  ])('does not navigate learn more to %s', (url) => {
    const { container } = renderListedCard(url);
    expect(unsafeHrefs(container)).toEqual([]);
  });
});
