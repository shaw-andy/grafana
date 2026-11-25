import { credentialedResourceUrls } from 'test/credentialedResourceUrls';

import { renderMarkdown, renderTextPanelMarkdown } from './markdown';
import { sanitize, sanitizeTextPanelContent } from './sanitize';

const payloads = [
  'visible ![alt](/logout)',
  'visible ![alt](/profile/switch-org/2)',
  'visible ![alt](./logout)',
  'visible ![alt](../logout)',
  'visible <img src="/logout">',
  'visible <img src="/profile/switch-org/2">',
  'visible <img src="&#47;logout">',
  'visible <img srcset="/logout 1x">',
  'visible <audio src="/logout"></audio>',
  'visible <video poster="/logout"></video>',
  'visible <video src="/profile/switch-org/2"></video>',
  'visible <source src="/logout">',
  'visible <div style="background-image:url(/logout)"></div>',
  'visible <div style="background:url(&#39;/profile/switch-org/2&#39;)"></div>',
  'visible <iframe src="/logout"></iframe>',
  'visible <meta http-equiv="refresh" content="0;url=/logout">',
];

describe('markdown rendering does not emit credentialed subresource URLs', () => {
  it.each(payloads)('renderMarkdown keeps query text and drops credentialed URLs: %s', (payload) => {
    const html = renderMarkdown(payload);
    expect(credentialedResourceUrls(html)).toEqual([]);
    expect(html).toContain('visible');
  });

  it.each(payloads)('renderTextPanelMarkdown drops credentialed URLs: %s', (payload) => {
    const html = renderTextPanelMarkdown(payload);
    expect(credentialedResourceUrls(html)).toEqual([]);
    expect(html).toContain('visible');
  });

  it.each(payloads)('sanitizeTextPanelContent drops credentialed URLs: %s', (payload) => {
    expect(credentialedResourceUrls(sanitizeTextPanelContent(payload))).toEqual([]);
  });

  it.each(payloads)('DOMPurify sanitize used after unsanitized markdown drops credentialed URLs: %s', (payload) => {
    const html = sanitize(renderMarkdown(payload, { noSanitize: true }));
    expect(credentialedResourceUrls(html)).toEqual([]);
  });

  it('still renders an external image address', () => {
    const html = renderMarkdown('![cat](https://example.com/cat.png)');
    expect(html).toContain('https://example.com/cat.png');
    expect(credentialedResourceUrls(html)).toEqual([]);
  });
});
