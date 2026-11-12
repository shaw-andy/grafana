const placeholderToken = 'placeholder-token';

describe('loadUrlToken', () => {
  const originalLocation = window.location;

  afterEach(() => {
    Object.defineProperty(window, 'location', { configurable: true, value: originalLocation });
    jest.resetModules();
  });

  it('removes the URL login value from the address when it is read', async () => {
    await jest.isolateModulesAsync(async () => {
      Object.defineProperty(window, 'location', {
        configurable: true,
        value: {
          href: `http://grafana.example/d/abc?auth_token=${placeholderToken}&orgId=1`,
          origin: 'http://grafana.example',
          protocol: 'http:',
          host: 'grafana.example',
          hostname: 'grafana.example',
          pathname: '/d/abc',
          search: `?auth_token=${placeholderToken}&orgId=1`,
          hash: '',
          replace: jest.fn(),
        },
      });
      const replaceState = jest.spyOn(window.history, 'replaceState').mockImplementation((_, __, url) => {
        if (typeof url === 'string') {
          const next = new URL(url, 'http://grafana.example');
          window.location.href = next.href;
          window.location.pathname = next.pathname;
          window.location.search = next.search;
          window.location.hash = next.hash;
        }
      });

      const { loadUrlToken } = await import('./urlToken');
      loadUrlToken();

      const address = `${window.location.href} ${window.location.search} ${window.location.hash}`;
      const rewritten = replaceState.mock.calls.map((call) => String(call[2] ?? ''));
      const visible = [address, ...rewritten].join(' ');
      expect(visible).not.toContain(placeholderToken);
      expect(visible).not.toContain('auth_token');
    });
  });
});
