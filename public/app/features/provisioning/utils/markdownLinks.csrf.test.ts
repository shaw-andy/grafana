import { credentialedResourceUrls } from 'test/credentialedResourceUrls';

import { renderMarkdown, textUtil } from '@grafana/data';
import { type RepositoryView } from 'app/api/clients/provisioning/v0alpha1';

import { rewriteRelativeMarkdownLinks } from './markdownLinks';

const repository: RepositoryView = {
  name: 'manifests',
  target: 'folder',
  title: 'Manifests',
  type: 'github',
  url: 'https://github.com/grafana/grafana-manifests',
  branch: 'main',
  workflows: [],
};

function readmeHtml(markdown: string): string {
  const html = renderMarkdown(markdown, { noSanitize: true });
  const rewritten = rewriteRelativeMarkdownLinks(html, { repository, baseDirInRepo: 'ops' });
  return textUtil.sanitize(rewritten);
}

describe('folder readme markdown', () => {
  it.each([
    'visible ![alt](https://grafana.example/logout)',
    'visible ![alt](https://grafana.example/profile/switch-org/2)',
    'visible <img src="https://grafana.example/logout">',
    'visible <audio src="https://grafana.example/logout"></audio>',
    'visible <div style="background-image:url(https://grafana.example/logout)"></div>',
    'visible <iframe src="https://grafana.example/logout"></iframe>',
  ])('does not leave a credentialed URL after rewrite and sanitize: %s', (markdown) => {
    const html = readmeHtml(markdown);
    expect(credentialedResourceUrls(html)).toEqual([]);
    expect(html).toContain('visible');
  });

  it('rewrites a root-relative image away from the Grafana origin', () => {
    const html = readmeHtml('visible ![alt](/logout)');
    expect(credentialedResourceUrls(html)).toEqual([]);
    expect(html).not.toContain('src="/logout"');
  });
});
