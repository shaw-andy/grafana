import { render } from '@testing-library/react';
import DangerouslySetHtmlContent from 'dangerously-set-html-content';

import { TextMode } from './panelcfg.gen';
import { transformContent } from './v2/utils';

const SAFE_HTTPS = 'https://example.com/image.png';

function imageRequestsThisOrigin(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll('img'))
    .map((img) => img.src)
    .filter((src) => new URL(src).origin === window.location.origin);
}

function renderPanelHtml(html: string) {
  return render(<DangerouslySetHtmlContent html={html} />);
}

describe('text panel images and the viewer session', () => {
  it.each([
    [TextMode.HTML, `<img alt="" src="/logout"><img alt="" src="${SAFE_HTTPS}">`],
    [TextMode.Markdown, `![x](/logout)\n\n![x](${SAFE_HTTPS})`],
  ])('does not request this origin from %s content', (mode, content) => {
    const html = transformContent(mode, content, false);
    const { container } = renderPanelHtml(html);

    expect(container.querySelector(`img[src="${SAFE_HTTPS}"]`)?.getAttribute('src')).toBe(SAFE_HTTPS);
    expect(imageRequestsThisOrigin(container)).toEqual([]);
  });
});
