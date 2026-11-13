import { render } from '@testing-library/react';

import { type AnnotationEvent } from '@grafana/data';

import { AnnotationListItem } from './AnnotationListItem';
import { type Options } from './panelcfg.gen';

const SESSION_PATH = '/profile/switch-org/2';

const options: Options = {
  limit: 10,
  navigateAfter: '10m',
  navigateBefore: '10m',
  navigateToPanel: true,
  onlyFromThisDashboard: true,
  onlyInTimeRange: false,
  showTags: false,
  showTime: false,
  showUser: false,
  tags: [],
};

const MEDIA = [
  ['image', `<img src="${SESSION_PATH}" alt="">`],
  ['image with an entity-encoded path', `<img src="&#47;profile&#47;switch-org&#47;2" alt="">`],
  ['image srcset', `<img srcset="${SESSION_PATH} 1x" alt="">`],
  ['audio', `<audio src="${SESSION_PATH}"></audio>`],
  ['audio source', `<audio><source src="${SESSION_PATH}"></audio>`],
  ['video', `<video src="${SESSION_PATH}"></video>`],
  ['video poster', `<video poster="${SESSION_PATH}"></video>`],
] as const;

function loadableResourceUrls(root: ParentNode): string[] {
  const urls: string[] = [];
  root.querySelectorAll('[src], [srcset], [poster]').forEach((element) => {
    for (const attr of ['src', 'srcset', 'poster']) {
      const value = element.getAttribute(attr);
      if (value && value.trim() !== '') {
        urls.push(value);
      }
    }
  });
  return urls;
}

describe('annotation list stored media', () => {
  it.each(MEDIA)('does not load a same-origin %s from the stored text', (_label, markup) => {
    const annotation: AnnotationEvent = {
      text: `deploy note ${markup}`,
      time: 1700000000000,
    };

    const { container } = render(
      <AnnotationListItem
        options={options}
        annotation={annotation}
        formatDate={() => ''}
        onClick={() => {}}
        onAvatarClick={() => {}}
        onTagClick={() => {}}
      />
    );

    expect(container).toHaveTextContent('deploy note');
    const urls = loadableResourceUrls(container);
    expect(urls.filter((url) => url.includes(SESSION_PATH) || url.includes('profile/switch-org/2'))).toEqual([]);
  });
});
