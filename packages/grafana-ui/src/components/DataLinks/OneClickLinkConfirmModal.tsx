import { css } from '@emotion/css';
import { useMemo } from 'react';

import { type GrafanaTheme2, type LinkModel } from '@grafana/data';
import { t, Trans } from '@grafana/i18n';

import { useStyles2 } from '../../themes/ThemeContext';
import { ConfirmModal } from '../ConfirmModal/ConfirmModal';

interface OneClickLinkConfirmModalProps {
  link: LinkModel;
  onDismiss: () => void;
}

function resolveAddress(href: string): string {
  try {
    return new URL(href, document.baseURI).href;
  } catch {
    return href;
  }
}

/**
 * The link title is author-controlled, so a one-click link must show the viewer the address it opens,
 * and must open exactly that displayed address, before navigating.
 *
 * @internal
 */
export function OneClickLinkConfirmModal({ link, onDismiss }: OneClickLinkConfirmModalProps) {
  const styles = useStyles2(getStyles);
  const address = useMemo(() => resolveAddress(link.href), [link.href]);

  return (
    <ConfirmModal
      isOpen={true}
      title={t('grafana-ui.one-click-link-confirm-modal.title', 'Open link')}
      body={
        <>
          <Trans i18nKey="grafana-ui.one-click-link-confirm-modal.body">This link opens the following address:</Trans>
          <code className={styles.address}>{address}</code>
        </>
      }
      confirmText={t('grafana-ui.one-click-link-confirm-modal.confirm', 'Open link')}
      confirmVariant="primary"
      onConfirm={() => {
        onDismiss();
        window.open(address, link.target ?? '_self');
      }}
      onDismiss={onDismiss}
    />
  );
}

const getStyles = (theme: GrafanaTheme2) => ({
  address: css({
    display: 'block',
    marginTop: theme.spacing(1),
    padding: theme.spacing(1),
    fontFamily: theme.typography.fontFamilyMonospace,
    wordBreak: 'break-all',
    background: theme.colors.background.secondary,
    borderRadius: theme.shape.radius.default,
  }),
});
