import { Trans } from '@grafana/i18n';
import { LinkButton, Stack } from '@grafana/ui';
import { type RepositoryUrLs } from 'app/api/clients/provisioning/v0alpha1';

import { type JobType } from '../types';
import { sanitizeRepoLink } from '../utils/git';

interface Props {
  jobType?: JobType;
  urls?: RepositoryUrLs;
}
export function PullRequestButtons({ urls, jobType }: Props) {
  const pullRequestURL = toSafeLink(urls?.newPullRequestURL);
  const compareURL = toSafeLink(urls?.compareURL);
  const branchURL = toSafeLink(urls?.sourceURL);

  // Migrate is the only flow that reaches here via a sync job, and it just needs
  // the pull request. The branch/compare links are for delete/move jobs.
  const onlyPullRequest = jobType === 'sync';

  return (
    <Stack>
      {!onlyPullRequest && (
        <>
          <LinkButton href={branchURL} icon="external-link-alt" variant="secondary" target="_blank">
            <Trans i18nKey="provisioning.repository-link.delete-or-move-job.view-branch">View branch</Trans>
          </LinkButton>
          <LinkButton href={compareURL} icon="external-link-alt" variant="secondary" target="_blank">
            <Trans i18nKey="provisioning.repository-link.delete-or-move-job.compare-branch">Compare branch</Trans>
          </LinkButton>
        </>
      )}
      <LinkButton href={pullRequestURL} icon="external-link-alt" variant="secondary" target="_blank">
        <Trans i18nKey="provisioning.repository-link.delete-or-move-job.open-pull-request">Open pull request</Trans>
      </LinkButton>
    </Stack>
  );
}

function toSafeLink(url?: string) {
  if (!url) {
    return undefined;
  }
  return sanitizeRepoLink(url) ?? 'about:blank';
}
