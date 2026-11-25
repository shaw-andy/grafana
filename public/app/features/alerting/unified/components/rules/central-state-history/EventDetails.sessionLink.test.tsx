import { render, screen } from 'test/test-utils';

import { type TimeRange, dateTime } from '@grafana/data';
import { GrafanaAlertState } from 'app/types/unified-alerting-dto';

import { EventDetails } from './EventDetails';

const mockHistoryRule: { annotations: Record<string, string>; name: string; uid: string } = {
  annotations: {},
  name: 'history rule',
  uid: 'uid-1',
};

jest.mock('../../../hooks/useCombinedRule', () => ({
  useCombinedRule: () => ({ error: null, loading: false, result: mockHistoryRule }),
}));

jest.mock('../../../api/stateHistoryApi', () => ({
  stateHistoryApi: {
    useGetRuleHistoryQuery: () => ({
      currentData: undefined,
      isLoading: false,
      isError: false,
      error: undefined,
    }),
  },
}));

const SESSION_PATH = /^\/(?:logout|profile\/switch-org\/\d+)$/;

function resolvesToSessionAction(href: string): boolean {
  let url: URL;
  try {
    url = new URL(href, window.location.href);
  } catch {
    return false;
  }
  if (url.host !== window.location.host) {
    return false;
  }
  let path = url.pathname;
  try {
    path = decodeURIComponent(path);
  } catch {
    return false;
  }
  if (path.length > 1 && path.endsWith('/')) {
    path = path.slice(0, -1);
  }
  return SESSION_PATH.test(path);
}

describe('state history event annotations', () => {
  const origin = window.location.origin;
  const logout = `${origin}/logout`;
  const switchOrg = `${origin}/profile/../profile/switch-org/4`;

  it('does not link rule annotations at logout or organization switch', () => {
    mockHistoryRule.annotations = {
      summary: logout,
      description: switchOrg,
      custom_note: `${origin}/%6cogout`,
    };

    const record = {
      timestamp: Date.now(),
      line: {
        previous: GrafanaAlertState.Normal,
        current: GrafanaAlertState.Alerting,
        labels: { instance: 'i-123' },
        ruleUID: 'grafana/uid-1',
      },
    };
    const timeRange: TimeRange = {
      from: dateTime(0),
      to: dateTime(1),
      raw: { from: dateTime(0), to: dateTime(1) },
    };

    render(<EventDetails record={record} addFilter={jest.fn()} timeRange={timeRange} />);

    expect(screen.getByText(logout)).toBeInTheDocument();
    expect(screen.getByText(switchOrg)).toBeInTheDocument();
    expect(screen.getByText(`${origin}/%6cogout`)).toBeInTheDocument();
    const hrefs = screen
      .queryAllByRole('link')
      .map((anchor) => anchor.getAttribute('href') ?? '')
      .filter((href) => resolvesToSessionAction(href));
    expect(hrefs).toEqual([]);
  });
});
