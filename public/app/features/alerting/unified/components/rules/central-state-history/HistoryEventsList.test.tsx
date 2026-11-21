import { HttpResponse, http } from 'msw';
import { render, screen, waitFor } from 'test/test-utils';
import { byLabelText, byTestId } from 'testing-library-selector';

import { type DataFrameJSON, getDefaultTimeRange } from '@grafana/data';
import { config } from '@grafana/runtime';

import { setupMswServer } from '../../../mockApi';
import { captureRequests } from '../../../mocks/server/events';

import { getHistory } from './CentralHistoryRuntimeDataSource';
import { HistoryEventsList } from './EventListSceneObject';
import { StateFilterValues } from './constants';

const server = setupMswServer();
// msw server is setup to intercept the history api call and return the mocked data by default
// that consists in 4 rows.
// 2 rows for alert1 and 2 rows for alert2

const ui = {
  rowHeader: byTestId('event-row-header'),
  loadingBar: byLabelText('Loading bar'),
};
describe('HistoryEventsList', () => {
  it('should render the full list correctly when no filters are applied', async () => {
    render(
      <HistoryEventsList
        valueInLabelFilter={''}
        valueInStateToFilter={StateFilterValues.all}
        valueInStateFromFilter={StateFilterValues.all}
        addFilter={jest.fn()}
        timeRange={getDefaultTimeRange()}
      />
    );
    await waitFor(() => {
      expect(ui.loadingBar.query()).not.toBeInTheDocument();
    });
    expect(ui.rowHeader.getAll()).toHaveLength(4);
  });
  it('should render the list correctly filtered by label in filter variable', async () => {
    render(
      <HistoryEventsList
        valueInLabelFilter={'alertname=alert1'}
        valueInStateToFilter={StateFilterValues.all}
        valueInStateFromFilter={StateFilterValues.all}
        addFilter={jest.fn()}
        timeRange={getDefaultTimeRange()}
      />
    );
    await waitFor(() => {
      expect(ui.loadingBar.query()).not.toBeInTheDocument();
    });
    expect(ui.rowHeader.getAll()).toHaveLength(2); // 2 events for alert1
    expect(ui.rowHeader.getAll()[0]).toHaveTextContent(
      'June 14 at 06:39:00alert1alertnamealert1grafana_folderFOLDER Ahandler/alerting/*'
    );
    expect(ui.rowHeader.getAll()[1]).toHaveTextContent(
      'June 14 at 06:38:30alert1alertnamealert1grafana_folderFOLDER Ahandler/alerting/*'
    );
  });

  it('should render the list correctly filtered by from and to state ', async () => {
    render(
      <HistoryEventsList
        valueInLabelFilter={''}
        valueInStateFromFilter={StateFilterValues.firing}
        valueInStateToFilter={StateFilterValues.normal}
        addFilter={jest.fn()}
        timeRange={getDefaultTimeRange()}
      />
    );
    await waitFor(() => {
      expect(ui.loadingBar.query()).not.toBeInTheDocument();
    });
    expect(ui.rowHeader.getAll()).toHaveLength(1);
    expect(ui.rowHeader.getAll()[0]).toHaveTextContent(
      'June 14 at 06:38:30alert2alertnamealert2grafana_folderFOLDER Ahandler/alerting/*'
    );
  });

  it('should render the list correctly filtered by state to', async () => {
    render(
      <HistoryEventsList
        valueInLabelFilter={''}
        valueInStateToFilter={StateFilterValues.firing}
        valueInStateFromFilter={StateFilterValues.all}
        addFilter={jest.fn()}
        timeRange={getDefaultTimeRange()}
      />
    );
    await waitFor(() => {
      expect(ui.loadingBar.query()).not.toBeInTheDocument();
    });
    expect(ui.rowHeader.getAll()).toHaveLength(2);
    expect(ui.rowHeader.getAll()[0]).toHaveTextContent(
      'June 14 at 06:39:00alert2alertnamealert2grafana_folderFOLDER Ahandler/alerting/*'
    );
    expect(ui.rowHeader.getAll()[1]).toHaveTextContent(
      'June 14 at 06:38:30alert1alertnamealert1grafana_folderFOLDER Ahandler/alerting/*'
    );
  });
  it('should render the list correctly filtered by state from', async () => {
    render(
      <HistoryEventsList
        valueInLabelFilter={''}
        valueInStateFromFilter={StateFilterValues.firing}
        valueInStateToFilter={StateFilterValues.all}
        addFilter={jest.fn()}
        timeRange={getDefaultTimeRange()}
      />
    );
    await waitFor(() => {
      expect(ui.loadingBar.query()).not.toBeInTheDocument();
    });
    expect(ui.rowHeader.getAll()).toHaveLength(1);
    expect(ui.rowHeader.getAll()[0]).toHaveTextContent(
      'June 14 at 06:38:30alert2alertnamealert2grafana_folderFOLDER Ahandler/alerting/*'
    );
  });

  it('should render the list correctly filtered by label and state to', async () => {
    render(
      <HistoryEventsList
        valueInLabelFilter={'alertname=alert1'}
        valueInStateToFilter={StateFilterValues.firing}
        valueInStateFromFilter={StateFilterValues.all}
        addFilter={jest.fn()}
        timeRange={getDefaultTimeRange()}
      />
    );
    await waitFor(() => {
      expect(ui.loadingBar.query()).not.toBeInTheDocument();
    });
    expect(ui.rowHeader.getAll()).toHaveLength(1);
    expect(ui.rowHeader.getAll()[0]).toHaveTextContent(
      'June 14 at 06:38:30alert1alertnamealert1grafana_folderFOLDER Ahandler/alerting/*'
    );
  });

  it('should handle an empty list when no events match the filter criteria', async () => {
    render(
      <HistoryEventsList
        valueInLabelFilter={'nonexistentlabel=xyz'}
        valueInStateToFilter={StateFilterValues.all}
        valueInStateFromFilter={StateFilterValues.all}
        addFilter={jest.fn()}
        timeRange={getDefaultTimeRange()}
      />
    );
    await waitFor(() => {
      expect(ui.loadingBar.query()).not.toBeInTheDocument();
    });
    expect(ui.rowHeader.query()).not.toBeInTheDocument();
  });

  describe('backend filtering', () => {
    it('should send all matchers (including regex and negation) to the backend via the matchers param', async () => {
      const capture = captureRequests((req) => req.url.includes('/api/v1/rules/history'));

      render(
        <HistoryEventsList
          valueInLabelFilter={'alertname=alert1, grafana_folder=~".*folder.*", severity!="high", team="alerting"'}
          valueInStateToFilter={StateFilterValues.all}
          valueInStateFromFilter={StateFilterValues.all}
          addFilter={jest.fn()}
          timeRange={getDefaultTimeRange()}
        />
      );

      await waitFor(() => {
        expect(ui.loadingBar.query()).not.toBeInTheDocument();
      });

      const requests = await capture;
      expect(requests).toHaveLength(1);

      const url = new URL(requests[0].url);

      // All matchers are forwarded as a single `matchers` selector param.
      const matchersParam = url.searchParams.get('matchers');
      expect(matchersParam).not.toBeNull();
      expect(matchersParam).toContain('alertname=alert1');
      expect(matchersParam).toContain('grafana_folder=~".*folder.*"');
      expect(matchersParam).toContain('severity!="high"');
      expect(matchersParam).toContain('team="alerting"');

      // Legacy per-label params must not be used anymore.
      expect(url.searchParams.get('labels_alertname')).toBeNull();
      expect(url.searchParams.get('labels_team')).toBeNull();
    });

    it('should forward the matchers string to chart data via getHistory function', async () => {
      const capture = captureRequests((req) => req.url.includes('/api/v1/rules/history'));

      const from = 123;
      const to = 456;
      const matchers = '{alertname="alert_1",team="alerting"}';

      await getHistory(from, to, matchers);

      const requests = await capture;
      expect(requests).toHaveLength(1);

      const url = new URL(requests[0].url);

      expect(url.searchParams.get('matchers')).toBe(matchers);
      expect(url.searchParams.get('from')).toBe(from.toString());
      expect(url.searchParams.get('to')).toBe(to.toString());
    });
  });

  describe('rule link from a state-history log line', () => {
    function historyFrame(ruleUID: string): DataFrameJSON {
      return {
        data: {
          values: [
            [1_700_000_000_000],
            [
              {
                previous: 'Normal',
                current: 'Alerting',
                ruleUID,
                labels: { alertname: 'Disk almost full' },
              },
            ],
            [{ from: 'state-history', orgID: '1' }],
          ],
        },
      };
    }

    function renderHistory(ruleUID: string) {
      server.use(http.get('/api/v1/rules/history', () => HttpResponse.json(historyFrame(ruleUID))));
      render(
        <HistoryEventsList
          valueInLabelFilter={''}
          valueInStateToFilter={StateFilterValues.all}
          valueInStateFromFilter={StateFilterValues.all}
          addFilter={jest.fn()}
          timeRange={getDefaultTimeRange()}
        />
      );
    }

    function requestUrl(href: string): URL {
      return new URL(href, 'http://grafana.example');
    }

    it('keeps a short rule uid on the rule view path', async () => {
      renderHistory('abc_DEF-123');
      const link = await screen.findByRole('link', { name: 'Disk almost full' });
      const subPath = config.appSubUrl ?? '';
      expect(requestUrl(link.getAttribute('href') ?? '').pathname).toBe(
        `${subPath}/alerting/grafana/abc_DEF-123/view`
      );
    });

    it.each([
      ['../../../logout?', '/logout'],
      ['../../../profile/switch-org/2?', '/profile/switch-org/2'],
    ])('does not let ruleUID %s navigate to %s', async (ruleUID, escapedPath) => {
      renderHistory(ruleUID);
      const header = await screen.findByTestId('event-row-header');
      expect(header).toHaveTextContent('Disk almost full');
      const link = header.querySelector('a');
      if (link) {
        const url = requestUrl(link.getAttribute('href') ?? '');
        const subPath = config.appSubUrl ?? '';
        expect(url.origin).toBe('http://grafana.example');
        expect(url.pathname.startsWith(`${subPath}/alerting/grafana/`)).toBe(true);
        expect(url.pathname).not.toBe(escapedPath);
      }
    });
  });
});
