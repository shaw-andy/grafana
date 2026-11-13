import { css } from '@emotion/css';

import { type GrafanaTheme2 } from '@grafana/data';
import { t } from '@grafana/i18n';

import { useStyles2 } from '../../themes/ThemeContext';

interface Props {
  method: string;
  url: string;
  body?: string;
}

/**
 * Shows the request an action will send so the user can confirm the exact values.
 * @internal
 */
export function ActionRequestDetails({ method, url, body }: Props) {
  const styles = useStyles2(getStyles);

  return (
    <div className={styles.container}>
      <p>
        {t(
          'grafana-ui.action-request-details.description',
          'This will send the following request using your Grafana session.'
        )}
      </p>
      <dl className={styles.list}>
        <dt className={styles.term}>{t('grafana-ui.action-request-details.method', 'Method')}</dt>
        <dd className={styles.value}>
          <code>{method}</code>
        </dd>
        <dt className={styles.term}>{t('grafana-ui.action-request-details.url', 'URL')}</dt>
        <dd className={styles.value}>
          <code>{url}</code>
        </dd>
        {body !== undefined && (
          <>
            <dt className={styles.term}>{t('grafana-ui.action-request-details.body', 'Body')}</dt>
            <dd className={styles.value}>
              <pre className={styles.body}>{body}</pre>
            </dd>
          </>
        )}
      </dl>
    </div>
  );
}

const getStyles = (theme: GrafanaTheme2) => ({
  container: css({
    marginTop: theme.spacing(2),
    textAlign: 'left',
  }),
  list: css({
    display: 'grid',
    gridTemplateColumns: 'max-content 1fr',
    gap: theme.spacing(1, 2),
    margin: 0,
  }),
  term: css({
    fontWeight: theme.typography.fontWeightMedium,
  }),
  value: css({
    margin: 0,
    minWidth: 0,
    wordBreak: 'break-all',
  }),
  body: css({
    margin: 0,
    maxHeight: '200px',
    overflow: 'auto',
    whiteSpace: 'pre-wrap',
  }),
});
