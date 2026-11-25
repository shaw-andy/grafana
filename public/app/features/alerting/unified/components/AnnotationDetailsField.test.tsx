import { screen } from '@testing-library/react';
import { render } from 'test/test-utils';

import { AlertState } from 'app/plugins/datasource/alertmanager/types';
import { GrafanaAlertState } from 'app/types/unified-alerting-dto';

import { sessionActionHrefs } from '../testSetup/sessionActionHref';

import { AlertDetails } from './alert-groups/AlertDetails';
import { AnnotationDetailsField } from './AnnotationDetailsField';
import { AlertInstanceDetails } from './rules/AlertInstanceDetails';

const annotationUrls = [
  `${window.location.origin}/logout`,
  `${window.location.origin}/logout/`,
  `${window.location.origin}/%6Cogout`,
  `${window.location.origin}/profile/switch-org/2`,
  `${window.location.origin}/profile/switch-org/%32`,
  `http://viewer@${window.location.host}/logout`,
];

describe('annotation field session actions', () => {
  it.each(annotationUrls)('does not link a custom annotation to a session action: %s', (annotationUrl) => {
    const { container } = render(<AnnotationDetailsField annotationKey="doc" value={annotationUrl} />);

    expect(screen.getByText(annotationUrl)).toBeInTheDocument();
    expect(sessionActionHrefs(container)).toEqual([]);
  });

  it.each(annotationUrls)('does not link a summary annotation to a session action: %s', (annotationUrl) => {
    const { container } = render(<AnnotationDetailsField annotationKey="summary" value={annotationUrl} />);

    expect(screen.getByText(annotationUrl)).toBeInTheDocument();
    expect(sessionActionHrefs(container)).toEqual([]);
  });

  it('alert group details pass a firing alert annotation through without a session-action link', () => {
    const logoutUrl = `${window.location.origin}/logout`;
    const { container } = render(
      <AlertDetails
        alertManagerSourceName="grafana"
        alert={{
          startsAt: '2026-03-08T11:55:00Z',
          updatedAt: '2026-03-08T11:55:00Z',
          endsAt: '2026-03-08T12:00:00Z',
          labels: { alertname: 'HighCPU' },
          annotations: { summary: logoutUrl },
          receivers: [{ name: 'slack' }],
          fingerprint: 'fp',
          status: { state: AlertState.Active, silencedBy: [], inhibitedBy: [] },
        }}
      />
    );

    expect(screen.getByText(logoutUrl)).toBeInTheDocument();
    expect(sessionActionHrefs(container)).toEqual([]);
  });

  it('alert instance details pass an annotation through without a session-action link', () => {
    const switchOrgUrl = `${window.location.origin}/profile/switch-org/2`;
    const { container } = render(
      <AlertInstanceDetails
        instance={{
          activeAt: '',
          annotations: { runbook_url: switchOrgUrl },
          labels: {},
          state: GrafanaAlertState.Alerting,
          value: '',
        }}
      />
    );

    expect(screen.getByText(switchOrgUrl)).toBeInTheDocument();
    expect(sessionActionHrefs(container)).toEqual([]);
  });
});
