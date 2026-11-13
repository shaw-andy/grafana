import { skipToken } from '@reduxjs/toolkit/query/react';

import { config } from '@grafana/runtime';
import { type RepositoryView, useGetFrontendSettingsQuery } from 'app/api/clients/provisioning/v0alpha1';
import { useUrlParams } from 'app/core/navigation/hooks';

import { type RepoType } from '../Wizard/types';
import { isValidRepoType } from '../guards';

const K8S_NAME_RE = /^[a-z0-9][a-z0-9-]{0,252}$/;

export const usePullRequestParam = () => {
  const [params] = useUrlParams();
  const prParam = params.get('pull_request_url');
  const newPrParam = params.get('new_pull_request_url');
  const repoUrl = params.get('repo_url');
  const repoType = params.get('repo_type');
  const resourcePushedTo = params.get('resource_pushed_to');
  const actionParam = params.get('action');
  const prTitleParam = params.get('pr_title');
  const decodedRepoType = repoType ? decodeURIComponent(repoType) : undefined;
  const decodedResourcePushedTo = resourcePushedTo ? decodeURIComponent(resourcePushedTo) : undefined;
  const validRepoType = isValidRepoType(decodedRepoType) ? decodedRepoType : undefined;

  const hasUrlParam = Boolean(prParam || newPrParam || repoUrl);
  const { data: settings } = useGetFrontendSettingsQuery(
    config.provisioningEnabled && hasUrlParam ? undefined : skipToken
  );
  const repositories = settings?.items ?? [];

  return {
    prURL: getRepositoryLink(prParam, repositories, validRepoType),
    newPrURL: getRepositoryLink(newPrParam, repositories, validRepoType),
    repoURL: getRepositoryBaseUrl(repoUrl, repositories, validRepoType),
    repoType: validRepoType,
    resourcePushedTo:
      decodedResourcePushedTo && K8S_NAME_RE.test(decodedResourcePushedTo) ? decodedResourcePushedTo : undefined,
    action: actionParam === 'create' || actionParam === 'delete' || actionParam === 'update' ? actionParam : undefined,
    // useUrlParams reads via URLSearchParams.get, which already percent-decodes; re-sanitize the
    // single-line shape defensively in case the param was hand-crafted in the URL.
    prTitle: prTitleParam ? prTitleParam.replace(/\s+/g, ' ').trim().slice(0, 255) : undefined,
  };
};

// Anyone can craft these query params, and the banners label the link as the repository's pull
// request. So a link is only returned when it points inside a repository saved in Grafana (of the
// given type, since that drives the label); anything else is dropped rather than sanitized.
function getRepositoryLink(
  param: string | null,
  repositories: RepositoryView[],
  repoType: RepoType | undefined
): string | undefined {
  const url = parseQueryUrl(param);
  if (!url || !findRepository(url, repositories, repoType)) {
    return undefined;
  }
  return url.href;
}

function getRepositoryBaseUrl(
  param: string | null,
  repositories: RepositoryView[],
  repoType: RepoType | undefined
): string | undefined {
  const url = parseQueryUrl(param);
  return url ? findRepository(url, repositories, repoType)?.url : undefined;
}

function findRepository(
  url: URL,
  repositories: RepositoryView[],
  repoType: RepoType | undefined
): RepositoryView | undefined {
  return repositories.find((repo) => (!repoType || repo.type === repoType) && isInsideRepository(url, repo));
}

function isInsideRepository(url: URL, repo: RepositoryView): boolean {
  const base = parseHttpUrl(repo.url);
  if (!base || base.origin !== url.origin) {
    return false;
  }
  const basePath = base.pathname.replace(/\/+$/, '');
  // Providers may build links from the URL with or without a trailing ".git".
  return [basePath, basePath.replace(/\.git$/, '')].some(
    (prefix) => url.pathname === prefix || url.pathname.startsWith(`${prefix}/`)
  );
}

// The backend escapes pull_request_url once more before adding it to the query (on top of the
// encoding URLSearchParams.get already undoes), so it is decoded a second time here.
function parseQueryUrl(param: string | null): URL | undefined {
  if (!param) {
    return undefined;
  }
  try {
    return parseHttpUrl(decodeURIComponent(param));
  } catch {
    return undefined;
  }
}

function parseHttpUrl(value: string | undefined): URL | undefined {
  if (!value) {
    return undefined;
  }
  try {
    const url = new URL(value);
    if ((url.protocol !== 'https:' && url.protocol !== 'http:') || url.username || url.password) {
      return undefined;
    }
    return url;
  } catch {
    return undefined;
  }
}
