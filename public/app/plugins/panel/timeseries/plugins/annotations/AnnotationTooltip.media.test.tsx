import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

import { type DataFrame, toDataFrame } from '@grafana/data';

import { AnnotationMarker } from './AnnotationMarker';
import { AnnotationTooltip } from './AnnotationTooltip';
import { AnnotationTooltipCluster } from './AnnotationTooltipCluster';
import { type AnnotationVals } from './types';

// Same field-name copy as AnnotationsPlugin getVals, after LegacyAnnotationServer.query
// turns the stored annotation JSON into a frame with toDataFrame.
function valsFromStoredAnnotations(events: Array<Record<string, unknown>>): AnnotationVals {
  const frame = toDataFrame(events);
  const vals: Record<string, unknown> = {};
  for (const field of frame.fields) {
    vals[field.name] = field.values;
  }
  return vals as AnnotationVals;
}

const SESSION_PATH = '/profile/switch-org/2';

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

function expectNoSessionResource(root: ParentNode) {
  const urls = loadableResourceUrls(root);
  expect(urls.filter((url) => url.includes(SESSION_PATH) || url.includes('profile/switch-org/2'))).toEqual([]);
}

describe('stored annotation media', () => {
  describe('pinned tooltip', () => {
    it.each(MEDIA)('does not load a same-origin %s from the stored text', (_label, markup) => {
      const annoVals = valsFromStoredAnnotations([
        {
          id: 7,
          time: 1700000000000,
          text: `deploy note ${markup}`,
          dashboardUID: 'dash-1',
          tags: ['release'],
        },
      ]);

      const { container } = render(
        <AnnotationTooltip annoVals={annoVals} annoIdx={0} timeZone="utc" isPinned={true} onClose={() => {}} />
      );

      expect(container).toHaveTextContent('deploy note');
      expectNoSessionResource(container);
    });

    it.each(MEDIA)('does not load a same-origin %s from the stored title', (_label, markup) => {
      const annoVals = valsFromStoredAnnotations([
        {
          id: 7,
          time: 1700000000000,
          text: 'deploy note',
          title: `region ${markup}`,
          dashboardUID: 'dash-1',
        },
      ]);

      const { container } = render(
        <AnnotationTooltip annoVals={annoVals} annoIdx={0} timeZone="utc" isPinned={true} onClose={() => {}} />
      );

      expect(container).toHaveTextContent('deploy note');
      expect(container).toHaveTextContent('region');
      expectNoSessionResource(container);
    });
  });

  describe('cluster tooltip', () => {
    it.each(MEDIA)('does not load a same-origin %s from another annotation in the cluster', (_label, markup) => {
      const annoVals = valsFromStoredAnnotations([
        { id: 1, time: 1700000000000, text: 'anchor', title: 'anchor title', clusterIdx: 0, isCluster: true },
        {
          id: 2,
          time: 1700000001000,
          text: `deploy note ${markup}`,
          title: `region ${markup}`,
          clusterIdx: 0,
          isCluster: false,
        },
      ]);

      const { container } = render(
        <AnnotationTooltipCluster
          annoVals={annoVals}
          annoIdx={0}
          timeZone="utc"
          isPinned={true}
          onClose={() => {}}
          onEdit={() => {}}
        />
      );

      expect(container).toHaveTextContent('deploy note');
      expect(container).toHaveTextContent('region');
      expectNoSessionResource(container);
    });
  });

  describe('annotation marker', () => {
    function storedFrame(text: string): { frame: DataFrame; annoVals: AnnotationVals } {
      const events = [
        {
          id: 7,
          time: 1700000000000,
          text,
          dashboardUID: 'dash-1',
        },
      ];
      return { frame: toDataFrame(events), annoVals: valsFromStoredAnnotations(events) };
    }

    it('does not load a same-origin image when the marker is pinned', () => {
      const { frame, annoVals } = storedFrame(`deploy note <img src="${SESSION_PATH}" alt="">`);
      render(
        <AnnotationMarker
          frame={frame}
          annoVals={annoVals}
          annoIdx={0}
          style={{}}
          canExecuteActions={false}
          setPinned={() => {}}
          isPinned={true}
          showTooltipOnHover={false}
          timeZone="utc"
          portalRoot={document.body}
          replaceVariables={(value) => value}
        />
      );

      const tooltip = screen.getByTestId('annotation-marker');
      expect(tooltip).toHaveTextContent('deploy note');
      expectNoSessionResource(tooltip);
    });

    it('does not load a same-origin image when the marker is hovered', async () => {
      const { frame, annoVals } = storedFrame(`deploy note <img src="${SESSION_PATH}" alt="">`);
      render(
        <AnnotationMarker
          frame={frame}
          annoVals={annoVals}
          annoIdx={0}
          style={{}}
          canExecuteActions={false}
          setPinned={() => {}}
          isPinned={false}
          showTooltipOnHover={true}
          timeZone="utc"
          portalRoot={document.body}
          replaceVariables={(value) => value}
        />
      );

      await userEvent.hover(screen.getByRole('button', { name: 'Annotation' }));

      const tooltip = screen.getByTestId('annotation-marker');
      expect(tooltip).toHaveTextContent('deploy note');
      expectNoSessionResource(tooltip);
    });
  });
});
