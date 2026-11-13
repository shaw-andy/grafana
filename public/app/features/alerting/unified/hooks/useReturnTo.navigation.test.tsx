import { type ReactElement } from 'react';
import { MemoryRouter } from 'react-router-dom-v5-compat';
import { render, renderHook, screen } from 'test/test-utils';

import { config } from '@grafana/runtime';

import { Title as PolicyTitle } from '../components/common/Title';
import { Title as RuleTitle } from '../components/rule-viewer/RuleViewer';
import { Title as GroupTitle } from '../group-details/Title';

import { useReturnTo } from './useReturnTo';

const PAGE_ORIGIN = 'http://localhost';

/**
 * Same-origin returnTo values whose path the URL parser keeps, and which a
 * browser then loads as a different host when that path is used as an href.
 */
const offSiteReturnTargets = [
  `${PAGE_ORIGIN}//attacker.example`,
  `${PAGE_ORIGIN}//attacker.example/login?next=1`,
  `${PAGE_ORIGIN}///attacker.example`,
  `${PAGE_ORIGIN}:80//attacker.example`,
  `${PAGE_ORIGIN}/\\attacker.example`,
  `${PAGE_ORIGIN}\\\\attacker.example`,
  `${PAGE_ORIGIN}/.//attacker.example`,
  `${PAGE_ORIGIN}/foo/..//attacker.example`,
  ` \n${PAGE_ORIGIN}//attacker.example`,
  `http://not-a-secret@localhost//attacker.example`,
  '//attacker.example',
  '/\\attacker.example',
];

const safeReturnTargets: Array<{ returnTo: string; href: string }> = [
  { returnTo: '/alerting/silences?x=1', href: '/alerting/silences?x=1' },
  { returnTo: `${PAGE_ORIGIN}/alerting/list?x=1`, href: '/alerting/list?x=1' },
  { returnTo: `${PAGE_ORIGIN}/foo//attacker.example`, href: '/foo//attacker.example' },
];

function renderWithReturnTo(ui: ReactElement, returnTo: string) {
  return render(ui, {
    historyOptions: {
      initialEntries: [`/alerting/routes?returnTo=${encodeURIComponent(returnTo)}`],
    },
  });
}

function expectReturnAnchor(link: HTMLElement, href: string) {
  if (!(link instanceof HTMLAnchorElement)) {
    throw new Error('return control did not render an anchor');
  }
  expect(link.href).toBe(`${PAGE_ORIGIN}${href}`);
  expect(link.getAttribute('href')).toBe(href);
  expect(new URL(link.href).hostname).toBe('localhost');
}

describe('alerting returnTo navigation', () => {
  beforeAll(() => {
    if (window.location.origin !== PAGE_ORIGIN) {
      throw new Error(`expected jsdom origin ${PAGE_ORIGIN}, got ${window.location.href}`);
    }
  });

  afterEach(() => {
    config.appSubUrl = '';
  });

  describe('useReturnTo', () => {
    it.each(offSiteReturnTargets)('rejects %s and keeps the fallback', (returnTo) => {
      const { result } = renderHook(() => useReturnTo('/alerting/list'), {
        wrapper: ({ children }) => (
          <MemoryRouter
            future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
            initialEntries={[{ search: `?returnTo=${encodeURIComponent(returnTo)}` }]}
          >
            {children}
          </MemoryRouter>
        ),
      });

      expect(result.current.returnTo).toBe('/alerting/list');
    });

    it.each(safeReturnTargets)('keeps a same-origin path for $returnTo', ({ returnTo, href }) => {
      const { result } = renderHook(() => useReturnTo('/alerting/list'), {
        wrapper: ({ children }) => (
          <MemoryRouter
            future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
            initialEntries={[{ search: `?returnTo=${encodeURIComponent(returnTo)}` }]}
          >
            {children}
          </MemoryRouter>
        ),
      });

      expect(result.current.returnTo).toBe(href);
    });

    it('rejects a double-slash path when Grafana is served from a subpath', () => {
      config.appSubUrl = '/grafana';
      const { result } = renderHook(() => useReturnTo('/alerting/list'), {
        wrapper: ({ children }) => (
          <MemoryRouter
            future={{ v7_startTransition: true, v7_relativeSplatPath: true }}
            initialEntries={[{ search: `?returnTo=${encodeURIComponent(`${PAGE_ORIGIN}//attacker.example`)}` }]}
          >
            {children}
          </MemoryRouter>
        ),
      });

      expect(result.current.returnTo).toBe('/alerting/list');
    });
  });

  describe('notification policy back link', () => {
    it.each(offSiteReturnTargets)('stays on this server for %s', async (returnTo) => {
      const { user } = renderWithReturnTo(
        <PolicyTitle name="Notification policy" returnToFallback="/alerting/routes" />,
        returnTo
      );
      const link = screen.getByRole('link', { name: 'Return to previous view' });
      link.addEventListener('click', (event) => event.preventDefault());
      await user.click(link);
      expectReturnAnchor(link, '/alerting/routes');
    });

    it('follows a same-origin returnTo path', () => {
      renderWithReturnTo(
        <PolicyTitle name="Notification policy" returnToFallback="/alerting/routes" />,
        `${PAGE_ORIGIN}/alerting/silences?x=1`
      );
      expectReturnAnchor(screen.getByRole('link', { name: 'Return to previous view' }), '/alerting/silences?x=1');
    });
  });

  describe('rule group back link', () => {
    it.each(offSiteReturnTargets)('stays on this server for %s', async (returnTo) => {
      const { user } = renderWithReturnTo(<GroupTitle name="CPU" />, returnTo);
      const link = screen.getByRole('link', { name: 'Back to alerting' });
      link.addEventListener('click', (event) => event.preventDefault());
      await user.click(link);
      expectReturnAnchor(link, '/alerting/list');
    });
  });

  describe('rule viewer back link', () => {
    it.each(offSiteReturnTargets)('stays on this server for %s', async (returnTo) => {
      const { user } = renderWithReturnTo(<RuleTitle name="CPU alert" returnToHref="/alerting/list" />, returnTo);
      const link = screen.getByRole('link', { name: 'Return to previous view' });
      link.addEventListener('click', (event) => event.preventDefault());
      await user.click(link);
      expectReturnAnchor(link, '/alerting/list');
    });
  });
});
