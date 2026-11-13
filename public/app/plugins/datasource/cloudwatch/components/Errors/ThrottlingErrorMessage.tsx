import { TextLink } from '@grafana/ui';

import { getServiceQuotasUrl } from '../../aws_url';

export interface Props {
  region: string;
}

export const ThrottlingErrorMessage = ({ region }: Props) => (
  <p>
    Please visit the&nbsp;
    <TextLink external href={getServiceQuotasUrl(region)}>
      AWS Service Quotas console
    </TextLink>
    &nbsp;to request a quota increase or see our&nbsp;
    <TextLink external href="https://grafana.com/docs/grafana/latest/datasources/cloudwatch/#manage-service-quotas">
      documentation
    </TextLink>
    &nbsp;to learn more.
  </p>
);
