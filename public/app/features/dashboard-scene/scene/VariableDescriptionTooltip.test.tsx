import { render, screen } from '@testing-library/react';

import { type Tooltip } from '@grafana/ui';

import { VariableDescriptionTooltip } from './VariableDescriptionTooltip';

function renderTooltipContent(content: React.ComponentProps<typeof Tooltip>['content']): React.ReactNode {
  if (typeof content === 'function') {
    return content({});
  }

  return content;
}

jest.mock('@grafana/ui', () => {
  const actual = jest.requireActual('@grafana/ui');

  return {
    ...actual,
    Tooltip: ({ content, children, interactive, placement }: React.ComponentProps<typeof Tooltip>) => (
      <div data-testid="mock-tooltip" data-interactive={interactive ? 'true' : 'false'} data-placement={placement}>
        <div data-testid="mock-tooltip-content">{renderTooltipContent(content)}</div>
        {children}
      </div>
    ),
  };
});

const SERVER = 'http://localhost:3000';

// Paths a top-level GET performs with the viewer's session cookie.
function isSessionChangingPath(pathname: string): boolean {
  const path = decodeURIComponent(pathname).replace(/\/+$/, '');
  return path === '/logout' || path.endsWith('/logout') || /\/profile\/switch-org\/\d+$/.test(path);
}

function isThisGrafanaHost(href: string): boolean {
  const url = new URL(href, SERVER);
  return url.hostname === 'localhost';
}

describe('VariableDescriptionTooltip', () => {
  it('renders markdown links as external links', () => {
    render(<VariableDescriptionTooltip description={'Read [docs](https://grafana.com/docs).'} placement="bottom" />);

    const link = screen.getByRole('link', { name: 'docs' });
    expect(link).toHaveAttribute('href', 'https://grafana.com/docs');
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  });

  it('renders bare links as external links', () => {
    render(<VariableDescriptionTooltip description={'Details: https://example.com/path?q=1.'} placement="bottom" />);

    const link = screen.getByRole('link', { name: 'https://example.com/path?q=1' });
    expect(link).toHaveAttribute('href', 'https://example.com/path?q=1');
    expect(link).toHaveAttribute('target', '_blank');
    expect(link).toHaveAttribute('rel', 'noopener noreferrer');
  });

  it('does not render unsafe links', () => {
    render(<VariableDescriptionTooltip description={'Do not click [this](javascript:alert(1))'} placement="bottom" />);

    expect(screen.queryByRole('link', { name: 'this' })).not.toBeInTheDocument();
    expect(screen.getByText(/this/)).toBeInTheDocument();
  });

  it('uses an interactive tooltip', () => {
    render(<VariableDescriptionTooltip description={'Read [docs](https://grafana.com/docs).'} placement="top" />);

    expect(screen.getByTestId('mock-tooltip')).toHaveAttribute('data-interactive', 'true');
  });

  // A custom label must not be the only thing the viewer sees for a link that
  // signs them out or changes their active organization. External documentation
  // links keep their labels. Showing the destination address as the link text
  // satisfies this, and so does not rendering the link.
  describe('session-changing links', () => {
    const cases: Array<{ name: string; description: string }> = [
      {
        name: 'logout on the default server URL',
        description: `See the [documentation](${SERVER}/logout).`,
      },
      {
        name: 'logout over https',
        description: 'See the [documentation](https://localhost:3000/logout).',
      },
      {
        name: 'logout without an explicit port',
        description: 'See the [documentation](http://localhost/logout).',
      },
      {
        name: 'logout with an uppercase scheme',
        description: 'See the [documentation](HTTP://localhost:3000/logout).',
      },
      {
        name: 'logout with a query string',
        description: `See the [documentation](${SERVER}/logout?continue=1).`,
      },
      {
        name: 'logout with a fragment',
        description: `See the [documentation](${SERVER}/logout#section).`,
      },
      {
        name: 'logout under a server subpath',
        description: `See the [documentation](${SERVER}/grafana/logout).`,
      },
      {
        name: 'percent-encoded logout path',
        description: `See the [documentation](${SERVER}/%6Cogout).`,
      },
      {
        name: 'logout path hidden by an HTML entity that sanitization decodes',
        description: `See the [documentation](${SERVER}/log&#111;ut).`,
      },
      {
        name: 'logout path hidden by a character that sanitization strips',
        description: `See the [documentation](${SERVER}/log${String.fromCharCode(0)}out).`,
      },
      {
        name: 'organization switch for an organization the viewer belongs to',
        description: `See the [documentation](${SERVER}/profile/switch-org/2).`,
      },
      {
        name: 'organization switch under a server subpath',
        description: `See the [documentation](${SERVER}/grafana/profile/switch-org/15).`,
      },
    ];

    it.each(cases)('does not disguise $name as documentation', ({ description }) => {
      render(<VariableDescriptionTooltip description={description} placement="bottom" />);

      const disguised = screen.queryByRole('link', {
        name: (accessibleName) => accessibleName.trim() === 'documentation',
      });
      expect(disguised).not.toBeInTheDocument();

      for (const link of screen.queryAllByRole('link')) {
        const href = link.getAttribute('href') ?? '';
        const url = new URL(href, SERVER);
        const labelHidesDestination = link.textContent?.trim() !== href && link.textContent?.trim() !== url.href;
        if (labelHidesDestination && isThisGrafanaHost(href) && isSessionChangingPath(url.pathname)) {
          throw new Error(`disguised session link ${link.textContent} -> ${href}`);
        }
      }
    });

    it('keeps an external documentation label beside a logout link', () => {
      render(
        <VariableDescriptionTooltip
          description={`Read the [docs](https://grafana.com/docs) or the [documentation](${SERVER}/logout).`}
          placement="bottom"
        />
      );

      expect(screen.getByRole('link', { name: 'docs' })).toHaveAttribute('href', 'https://grafana.com/docs');
      expect(
        screen.queryByRole('link', { name: (accessibleName) => accessibleName.trim() === 'documentation' })
      ).not.toBeInTheDocument();
    });
  });
});
