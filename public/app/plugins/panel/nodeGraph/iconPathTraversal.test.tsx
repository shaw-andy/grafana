import { render } from '@testing-library/react';
import { act } from 'react';
import { firstValueFrom } from 'rxjs';

import { type DataQueryRequest, type DataSourceInstanceSettings, FieldType, type IconName } from '@grafana/data';
import { Icon } from '@grafana/ui';
import { cacheStore } from 'react-inlinesvg';

import { TemplateSrv } from 'app/features/templating/template_srv';
import { TestDataDataSource } from 'app/plugins/datasource/grafana-testdata-datasource/datasource';
import { TestDataQueryType, type TestDataDataQuery } from 'app/plugins/datasource/grafana-testdata-datasource/dataquery';

import { Node } from './Node';
import { getGraphFrame, processNodes } from './utils';


// Enough ".." segments to climb out of public/build/img/icons/<subdir>/ back to the origin root.
// A trailing "?" or "&" makes the ".svg" suffix that getIconPath appends part of the query string.
const LOGOUT_ICON = '../../../../../logout?';
const ORG_SWITCH_ICON = '../../../../../api/search?orgId=2&';

interface SeenRequest {
  raw: string;
}

function installRequestRecorder(): { seen: SeenRequest[]; restore: () => void } {
  const seen: SeenRequest[] = [];
  const originalFetch = window.fetch;
  window.fetch = ((input: RequestInfo | URL) => {
    const raw = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    seen.push({ raw });
    return Promise.resolve(
      new Response('<svg xmlns="http://www.w3.org/2000/svg"></svg>', {
        status: 200,
        headers: { 'content-type': 'image/svg+xml' },
      })
    );
  }) as typeof window.fetch;

  return {
    seen,
    restore() {
      window.fetch = originalFetch;
    },
  };
}

function pathsOutsideIconDirectory(rawUrls: string[]): string[] {
  return rawUrls
    .map((raw) => {
      const url = new URL(raw, document.baseURI);
      return `${url.pathname}${url.search}`;
    })
    .filter((value) => !value.includes('/img/icons/'));
}

async function nodesFromRawFrame(icon: string) {
  const datasource = new TestDataDataSource(
    { type: 'grafana-testdata-datasource', uid: 'testdata' } as DataSourceInstanceSettings,
    new TemplateSrv()
  );
  const rawFrame = {
    name: 'nodes',
    fields: [
      { name: 'id', type: FieldType.string, values: ['node-1'] },
      { name: 'title', type: FieldType.string, values: ['service'] },
      { name: 'icon', type: FieldType.string, values: [icon] },
      { name: 'fixedX', type: FieldType.number, values: [12] },
      { name: 'fixedY', type: FieldType.number, values: [34] },
    ],
  };
  const response = await firstValueFrom(
    datasource.query({
      targets: [
        {
          refId: 'A',
          scenarioId: TestDataQueryType.RawFrame,
          rawFrameContent: JSON.stringify([rawFrame]),
        } as TestDataDataQuery,
      ],
    } as DataQueryRequest<TestDataDataQuery>)
  );
  const { nodes: frames } = getGraphFrame(response.data);
  const processed = processNodes(frames[0], undefined);
  return processed.nodes[0];
}

async function renderAndCollect(node: React.ReactElement): Promise<string[]> {
  const recorder = installRequestRecorder();
  try {
    await act(async () => {
      render(node);
      await new Promise((resolve) => setTimeout(resolve, 50));
    });
    const domSources = Array.from(document.querySelectorAll('svg'))
      .map((element) => element.getAttribute('id'))
      .filter((id): id is string => Boolean(id));
    return pathsOutsideIconDirectory([...recorder.seen.map((entry) => entry.raw), ...domSources]);
  } finally {
    recorder.restore();
  }
}

describe('node graph icon paths', () => {
  beforeEach(async () => {
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    await cacheStore.clear();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('does not request logout when a raw-frame icon field climbs out of the icon directory', async () => {
    const node = await nodesFromRawFrame(LOGOUT_ICON);
    expect(node.x).toBe(12);
    expect(node.y).toBe(34);

    const outside = await renderAndCollect(
      <svg>
        <Node node={node} onMouseEnter={() => {}} onMouseLeave={() => {}} onClick={() => {}} hovering="default" />
      </svg>
    );

    expect(outside).toEqual([]);
  });

  it('does not request an organization switch when a raw-frame icon field climbs out of the icon directory', async () => {
    const node = await nodesFromRawFrame(ORG_SWITCH_ICON);

    const outside = await renderAndCollect(
      <svg>
        <Node node={node} onMouseEnter={() => {}} onMouseLeave={() => {}} onClick={() => {}} hovering="default" />
      </svg>
    );

    expect(outside).toEqual([]);
  });
});

describe('Icon component paths', () => {
  beforeEach(async () => {
    jest.spyOn(console, 'warn').mockImplementation(() => {});
    await cacheStore.clear();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it.each([LOGOUT_ICON, ORG_SWITCH_ICON])(
    'does not fetch an icon name that is not in the built-in list (%s)',
    async (name) => {
      const outside = await renderAndCollect(<Icon name={name as IconName} size="xxxl" />);
      expect(outside).toEqual([]);
    }
  );
});
