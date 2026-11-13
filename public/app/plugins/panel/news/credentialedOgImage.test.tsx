/**
 * @jest-environment-options {"url": "http://localhost:3000/d/abc/my-dashboard"}
 */
import { render, screen, waitFor } from 'test/test-utils';

import { DataFrameView, EventBusSrv, getPanelOptionsWithDefaults } from '@grafana/data';

import { getPanelProps } from '../test-utils';

import { NewsPanel } from './NewsPanel';
import { parseAtomFeed } from './atom';
import { News } from './component/News';
import { plugin } from './module';
import { type Options } from './panelcfg.gen';
import { parseRSSFeed } from './rss';
import { type NewsItem } from './types';
import { feedToDataFrame } from './utils';

const DOCUMENT_URL = 'http://localhost:3000/d/abc/my-dashboard';
const THIS_ORIGIN = 'http://localhost:3000';
const FEED_URL = 'https://attacker.example/feed.xml';
const POST_URL = 'https://attacker.example/post';
const SAFE_IMAGE = 'https://cdn.example/news.png';

interface ImageCase {
  name: string;
  image: string;
  allow: boolean;
}

const imageCases: ImageCase[] = [
  { name: 'root-relative path', image: '/logout', allow: false },
  { name: 'root-relative org switch', image: '/profile/switch-org/2', allow: false },
  { name: 'path-relative', image: 'logout', allow: false },
  { name: 'dot path-relative', image: './api/org', allow: false },
  { name: 'parent path-relative', image: '../api/org', allow: false },
  { name: 'protocol-relative same host', image: '//localhost:3000/logout', allow: false },
  { name: 'absolute same origin', image: 'http://localhost:3000/logout', allow: false },
  { name: 'absolute same host with different case', image: 'HTTP://LOCALHOST:3000/logout', allow: false },
  { name: 'absolute same origin with a query', image: 'http://localhost:3000/logout?a=1&b=2', allow: false },
  { name: 'leading space', image: ' /logout', allow: false },
  { name: 'trailing newline', image: '/logout\n', allow: false },
  { name: 'leading tab', image: '\t/logout', allow: false },
  { name: 'https on this host', image: 'https://localhost:3000/logout', allow: false },
  { name: 'userinfo on this host', image: 'http://viewer@localhost:3000/logout', allow: false },
  { name: 'protocol-relative other host', image: '//cdn.example/news.png', allow: false },
  { name: 'javascript url', image: 'javascript:alert(1)', allow: false },
  { name: 'external https', image: SAFE_IMAGE, allow: true },
  { name: 'external http', image: 'http://cdn.example/news.png', allow: true },
  { name: 'different host that contains this hostname', image: 'http://localhost.evil.example/logout', allow: true },
  {
    name: 'different host with this origin in the query',
    image: 'http://evil.example/logout?next=http://localhost:3000/logout',
    allow: true,
  },
];

function xmlAttr(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/\n/g, '&#10;')
    .replace(/\t/g, '&#9;')
    .replace(/\r/g, '&#13;');
}

function rssFeed(image: string): string {
  return `<?xml version="1.0"?><rss version="2.0"><channel><item><title>Forced action</title><link>${POST_URL}</link><pubDate>Thu, 10 Feb 2022 16:00:17 +0000</pubDate><description>A post</description><meta property="og:image" content="${xmlAttr(image)}"/></item></channel></rss>`;
}

function atomFeed(image: string): string {
  return `<?xml version="1.0"?><feed xmlns="http://www.w3.org/2005/Atom"><entry><title>Forced action</title><link href="${POST_URL}"/><published>2022-02-12T08:00:00+00:00</published><content>A post</content><meta property="og:image" content="${xmlAttr(image)}"/></entry></feed>`;
}

function installImageSourceTracker() {
  const assigned: string[] = [];
  const originalSetAttribute = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function (name: string, value: string) {
    if (this instanceof HTMLImageElement && (name === 'src' || name === 'srcset')) {
      assigned.push(String(value));
    }
    return originalSetAttribute.call(this, name, value);
  };

  const descriptor = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, 'src');
  if (descriptor?.set && descriptor.get) {
    Object.defineProperty(HTMLImageElement.prototype, 'src', {
      configurable: true,
      enumerable: descriptor.enumerable,
      get: descriptor.get,
      set(value: string) {
        assigned.push(String(value));
        descriptor.set!.call(this, value);
      },
    });
  }

  return {
    assigned,
    restore() {
      Element.prototype.setAttribute = originalSetAttribute;
      if (descriptor) {
        Object.defineProperty(HTMLImageElement.prototype, 'src', descriptor);
      }
    },
  };
}

function resolvedHref(value: string): string | null {
  try {
    return new URL(value, DOCUMENT_URL).href;
  } catch {
    return null;
  }
}

function observedImageAddresses(assigned: string[]): string[] {
  const values = [...assigned];
  document.querySelectorAll('img').forEach((img) => {
    const attr = img.getAttribute('src');
    if (attr) {
      values.push(attr);
    }
    if (img.src) {
      values.push(img.src);
    }
    const srcset = img.getAttribute('srcset');
    if (srcset) {
      values.push(srcset);
    }
  });
  return values;
}

function sawResolvedAddress(raw: string, assigned: string[]): boolean {
  const expected = resolvedHref(raw);
  if (!expected) {
    return false;
  }
  return observedImageAddresses(assigned).some((value) => resolvedHref(value) === expected);
}

function sawThisServer(assigned: string[]): boolean {
  return observedImageAddresses(assigned).some((value) => {
    const href = resolvedHref(value);
    return href !== null && new URL(href).origin === THIS_ORIGIN;
  });
}

describe('News feed images', () => {
  let tracker: ReturnType<typeof installImageSourceTracker>;

  beforeEach(() => {
    expect(window.location.href).toBe(DOCUMENT_URL);
    tracker = installImageSourceTracker();
  });

  afterEach(() => {
    tracker.restore();
    jest.restoreAllMocks();
  });

  describe.each(['rss', 'atom'] as const)('%s og:image', (format) => {
    it.each(imageCases)('$name is rendered only when it cannot carry this server session', ({ image, allow }) => {
      const parsed = format === 'rss' ? parseRSSFeed(rssFeed(image)) : parseAtomFeed(atomFeed(image));
      expect(parsed.items[0]?.ogImage).toBe(image);

      const data = new DataFrameView<NewsItem>(feedToDataFrame(parsed));
      render(<News data={data} index={0} showImage />);

      expect(screen.getByRole('link', { name: 'Forced action' })).toHaveAttribute('href', POST_URL);

      if (allow) {
        const img = document.querySelector('img');
        expect(img).not.toBeNull();
        expect(img?.src).toBe(resolvedHref(image));
        expect(sawThisServer(tracker.assigned)).toBe(false);
        return;
      }

      expect(sawResolvedAddress(image, tracker.assigned)).toBe(false);
      expect(sawThisServer(tracker.assigned)).toBe(false);
      expect(document.querySelector('img')).toBeNull();
    });
  });

  it.each(['rss', 'atom'] as const)(
    'does not request a same-server image when the %s panel is shown with its default options',
    async (format) => {
      const image = format === 'rss' ? '/logout' : '/profile/switch-org/2';
      const xml = format === 'rss' ? rssFeed(image) : atomFeed(image);
      const fetched: string[] = [];
      jest.spyOn(global, 'fetch').mockImplementation(async (input) => {
        const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
        fetched.push(url);
        if (url !== FEED_URL) {
          return new Response('', { status: 500 });
        }
        return new Response(xml, { status: 200, headers: { 'content-type': 'application/xml' } });
      });

      const { options } = getPanelOptionsWithDefaults({
        plugin,
        currentOptions: { feedUrl: FEED_URL },
        currentFieldConfig: { defaults: {}, overrides: [] },
        isAfterPluginChange: false,
      });
      const panelOptions = options as Options;
      expect(panelOptions.showImage).toBe(true);

      render(<NewsPanel {...getPanelProps(panelOptions, { eventBus: new EventBusSrv() })} />);

      await waitFor(() => {
        expect(screen.getByRole('link', { name: 'Forced action' })).toBeInTheDocument();
      });

      expect(fetched).toEqual([FEED_URL]);
      expect(sawResolvedAddress(image, tracker.assigned)).toBe(false);
      expect(sawThisServer(tracker.assigned)).toBe(false);
      expect(document.querySelector('img')).toBeNull();
    }
  );

  it('still shows an external image when show image is left at its default', async () => {
    jest.spyOn(global, 'fetch').mockImplementation(async (input) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (url !== FEED_URL) {
        return new Response('', { status: 500 });
      }
      return new Response(rssFeed(SAFE_IMAGE), { status: 200, headers: { 'content-type': 'application/xml' } });
    });

    const { options } = getPanelOptionsWithDefaults({
      plugin,
      currentOptions: { feedUrl: FEED_URL },
      currentFieldConfig: { defaults: {}, overrides: [] },
      isAfterPluginChange: false,
    });

    render(<NewsPanel {...getPanelProps(options as Options, { eventBus: new EventBusSrv() })} />);

    await waitFor(() => {
      expect(document.querySelector('img')?.src).toBe(SAFE_IMAGE);
    });
    expect(sawThisServer(tracker.assigned)).toBe(false);
  });

  it('does not load a same-server address read after the address that was checked', () => {
    const frame = feedToDataFrame(parseRSSFeed(rssFeed(SAFE_IMAGE)));
    const field = frame.fields.find((item) => item.name === 'ogImage');
    expect(field).toBeDefined();
    let reads = 0;
    let resetScheduled = false;
    const values = field!.values;
    field!.values = new Proxy(values, {
      get(target, prop, receiver) {
        if (prop === '0') {
          reads += 1;
          if (!resetScheduled) {
            resetScheduled = true;
            queueMicrotask(() => {
              reads = 0;
              resetScheduled = false;
            });
          }
          // The component reads the address once to decide and again for the image.
          // A later read must not be able to supply a different address.
          return reads === 1 ? SAFE_IMAGE : 'http://localhost:3000/logout';
        }
        return Reflect.get(target, prop, receiver);
      },
    }) as typeof values;

    render(<News data={new DataFrameView<NewsItem>(frame)} index={0} showImage />);

    expect(sawResolvedAddress('http://localhost:3000/logout', tracker.assigned)).toBe(false);
    expect(sawThisServer(tracker.assigned)).toBe(false);
    const img = document.querySelector('img');
    if (img) {
      expect(img.src).toBe(SAFE_IMAGE);
    }
  });
});
