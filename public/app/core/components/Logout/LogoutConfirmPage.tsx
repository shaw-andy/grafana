import { Trans } from '@grafana/i18n';
import { config } from '@grafana/runtime';
import { Button, LinkButton, Stack, Text } from '@grafana/ui';
import { signOut } from 'app/core/utils/signOut';

import { InnerBox, LoginLayout } from '../Login/LoginLayout';

export const LogoutConfirmPage = () => (
  <LoginLayout>
    <InnerBox>
      <Stack direction="column" gap={2}>
        <Text element="p">
          <Trans i18nKey="logout.confirm-page.message">Do you want to sign out?</Trans>
        </Text>
        <Stack gap={2}>
          <Button onClick={signOut}>
            <Trans i18nKey="logout.confirm-page.sign-out">Sign out</Trans>
          </Button>
          <LinkButton variant="secondary" href={`${config.appSubUrl}/`}>
            <Trans i18nKey="logout.confirm-page.cancel">Cancel</Trans>
          </LinkButton>
        </Stack>
      </Stack>
    </InnerBox>
  </LoginLayout>
);

export default LogoutConfirmPage;
