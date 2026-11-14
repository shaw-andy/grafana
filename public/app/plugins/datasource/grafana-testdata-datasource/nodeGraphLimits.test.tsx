import { fireEvent, render, screen } from '@testing-library/react';
import { firstValueFrom } from 'rxjs';

import {
  dateTime,
  type DataQueryRequest,
  type DataQueryResponse,
  type DataSourceInstanceSettings,
  NodeGraphDataFrameFieldNames,
  type ScopedVars,
  type TimeRange,
} from '@grafana/data';
import { type TemplateSrv } from '@grafana/runtime';

import { NodeGraphEditor } from './components/NodeGraphEditor';
import { TestDataQueryType, type NodesQuery, type TestDataDataQuery } from './dataquery';
import { TestDataDataSource } from './datasource';

// Records the count passed into the real generator. A fix that builds the full
// graph and then trims the frames still fails, because the loop already ran.
const mockNodeCounts: unknown[] = [];
const mockEdgeCounts: unknown[] = [];

jest.mock('./nodeGraphUtils', () => {
  const actual = jest.requireActual('./nodeGraphUtils');
  return {
    ...actual,
    generateRandomNodes: (count?: number, seed?: number) => {
      mockNodeCounts.push(count);
      return actual.generateRandomNodes(count, seed);
    },
    generateRandomEdges: (count?: number, seed?: number) => {
      mockEdgeCounts.push(count);
      return actual.generateRandomEdges(count, seed);
    },
  };
});

// Ceiling a saved TestData node_graph query must enforce before it builds a graph.
// 1000 nodes is the largest graph this scenario may allocate for one panel query.
const MAX_NODE_GRAPH_NODES = 1000;

// A random graph of MAX nodes has one tree edge per extra node, plus at most
// floor(count/2)+1 extra edges. Those are 999 and 1500 for a ceiling of 1000.
const MIN_EDGES_AT_CEILING = 999;
const MAX_EDGES_AT_CEILING = 1500;

const templateSrv: TemplateSrv = {
  getVariables: () => [],
  replace: (target?: string) => target ?? '',
  containsTemplate: () => false,
  updateTimeRange: () => undefined,
};

function createDatasource() {
  const settings: DataSourceInstanceSettings = {
    uid: 'testdata',
    type: 'grafana-testdata-datasource',
    name: 'TestData',
    meta: {
      id: 'grafana-testdata-datasource',
      name: 'TestData',
      type: 'datasource',
      info: { author: { name: 'Grafana' }, version: '1.0.0', updated: '' },
      module: '',
      baseUrl: '',
    },
    jsonData: {},
    readOnly: false,
    access: 'proxy',
  };
  return new TestDataDataSource(settings, templateSrv);
}

function panelRequest(query: TestDataDataQuery): DataQueryRequest<TestDataDataQuery> {
  const from = dateTime('2020-01-01T00:00:00Z');
  const to = dateTime('2020-01-01T01:00:00Z');
  const range: TimeRange = { from, to, raw: { from: 'now-1h', to: 'now' } };
  const scopedVars: ScopedVars = {};
  return {
    requestId: 'panel-1',
    interval: '1s',
    intervalMs: 1000,
    range,
    scopedVars,
    targets: [query],
    timezone: 'utc',
    app: 'dashboard',
    startTime: 1_577_836_800_000,
  };
}

function savedNodeGraphQuery(nodes: {
  type?: NodesQuery['type'];
  count?: number | string;
  seed?: number;
}): TestDataDataQuery {
  return {
    refId: 'A',
    scenarioId: TestDataQueryType.NodeGraph,
    nodes: {
      type: nodes.type,
      seed: nodes.seed,
      // Dashboard JSON is not checked against the TypeScript type, so a count may arrive as a string.
      count: nodes.count as number | undefined,
    },
  };
}

function idCount(response: DataQueryResponse, frameIndex: number): number {
  const frame = response.data[frameIndex];
  const idField = frame.fields.find((field: { name: string }) => field.name === NodeGraphDataFrameFieldNames.id);
  if (!idField) {
    throw new Error(`frame ${frameIndex} has no id field`);
  }
  return idField.values.length;
}

async function runSavedQuery(nodes: { type?: NodesQuery['type']; count?: number | string; seed?: number }) {
  const datasource = createDatasource();
  return firstValueFrom(datasource.query(panelRequest(savedNodeGraphQuery(nodes))));
}

describe('saved TestData node_graph queries', () => {
  beforeEach(() => {
    mockNodeCounts.length = 0;
    mockEdgeCounts.length = 0;
  });

  it('builds one node per count when the saved count is within the ceiling', async () => {
    const response = await runSavedQuery({ type: 'random', count: 4, seed: 1 });

    expect(mockNodeCounts).toEqual([4]);
    expect(mockEdgeCounts).toEqual([]);
    expect(response.data).toHaveLength(2);
    expect(idCount(response, 0)).toBe(4);
  });

  it('uses ten nodes when a saved random query omits count', async () => {
    const response = await runSavedQuery({ type: 'random', seed: 1 });

    expect(mockNodeCounts).toEqual([undefined]);
    expect(idCount(response, 0)).toBe(10);
  });

  it('caps a saved random node_graph whose count is one past the ceiling', async () => {
    const response = await runSavedQuery({ type: 'random', count: MAX_NODE_GRAPH_NODES + 1, seed: 1 });

    expect(mockNodeCounts).toEqual([MAX_NODE_GRAPH_NODES]);
    expect(mockEdgeCounts).toEqual([]);
    expect(response.data).toHaveLength(2);
    expect(idCount(response, 0)).toBe(MAX_NODE_GRAPH_NODES);
    expect(idCount(response, 1)).toBeGreaterThanOrEqual(MIN_EDGES_AT_CEILING);
    expect(idCount(response, 1)).toBeLessThanOrEqual(MAX_EDGES_AT_CEILING);
  });

  it('caps a saved random node_graph whose count is 5000', async () => {
    const response = await runSavedQuery({ type: 'random', count: 5000, seed: 1 });

    expect(mockNodeCounts).toEqual([MAX_NODE_GRAPH_NODES]);
    expect(mockEdgeCounts).toEqual([]);
    expect(response.data).toHaveLength(2);
    expect(idCount(response, 0)).toBe(MAX_NODE_GRAPH_NODES);
    expect(idCount(response, 1)).toBeGreaterThanOrEqual(MIN_EDGES_AT_CEILING);
    expect(idCount(response, 1)).toBeLessThanOrEqual(MAX_EDGES_AT_CEILING);
  });

  it('caps a saved random node_graph when the count is a numeric string', async () => {
    const response = await runSavedQuery({ type: 'random', count: '5000', seed: 1 });

    expect(mockNodeCounts).toEqual([MAX_NODE_GRAPH_NODES]);
    expect(idCount(response, 0)).toBe(MAX_NODE_GRAPH_NODES);
  });

  it('caps a saved random edges query whose count is 5000 to the same ceiling', async () => {
    const response = await runSavedQuery({ type: 'random edges', count: 5000, seed: 1 });

    expect(mockEdgeCounts).toEqual([MAX_NODE_GRAPH_NODES]);
    expect(mockNodeCounts).toEqual([]);
    expect(response.data).toHaveLength(1);
    expect(idCount(response, 0)).toBeGreaterThanOrEqual(MIN_EDGES_AT_CEILING);
    expect(idCount(response, 0)).toBeLessThanOrEqual(MAX_EDGES_AT_CEILING);
  });

  it('caps a saved random query when the type is omitted and the count is 5000', async () => {
    const response = await runSavedQuery({ count: 5000, seed: 1 });

    expect(mockNodeCounts).toEqual([MAX_NODE_GRAPH_NODES]);
    expect(idCount(response, 0)).toBe(MAX_NODE_GRAPH_NODES);
  });

  it.each([0, -1, Number.NaN])('rejects a saved node count of %s before building a graph', async (count) => {
    await expect(runSavedQuery({ type: 'random', count, seed: 1 })).rejects.toThrow(/count/);
    expect(mockNodeCounts).toEqual([]);
    expect(mockEdgeCounts).toEqual([]);
  });

  it.each([0, -1, Number.NaN])('rejects a saved random edges count of %s before building a graph', async (count) => {
    await expect(runSavedQuery({ type: 'random edges', count, seed: 1 })).rejects.toThrow(/count/);
    expect(mockNodeCounts).toEqual([]);
    expect(mockEdgeCounts).toEqual([]);
  });

  it('rejects an infinite saved node count before building a graph', async () => {
    await expect(runSavedQuery({ type: 'random', count: Number.POSITIVE_INFINITY, seed: 1 })).rejects.toThrow(/count/);
    expect(mockNodeCounts).toEqual([]);
    expect(mockEdgeCounts).toEqual([]);
  });

  it('rejects an infinite saved random edges count before building a graph', async () => {
    await expect(runSavedQuery({ type: 'random edges', count: Number.POSITIVE_INFINITY, seed: 1 })).rejects.toThrow(
      /count/
    );
    expect(mockEdgeCounts).toEqual([]);
    expect(mockNodeCounts).toEqual([]);
  });

  it('caps a saved count above the safe integer range before building a graph', async () => {
    const response = await runSavedQuery({ type: 'random', count: 1e16, seed: 1 });

    expect(mockNodeCounts).toEqual([MAX_NODE_GRAPH_NODES]);
    expect(idCount(response, 0)).toBe(MAX_NODE_GRAPH_NODES);
  });
});

describe('NodeGraphEditor count ceiling', () => {
  it.each(['random', 'random edges'] as const)(
    'stores %s count 25 when the entered count is within the ceiling',
    (type) => {
      const onChange = jest.fn();
      render(
        <NodeGraphEditor
          onChange={onChange}
          query={{ refId: 'A', scenarioId: TestDataQueryType.NodeGraph, nodes: { type, count: 10, seed: 7 } }}
        />
      );

      fireEvent.change(screen.getByRole('spinbutton', { name: 'Count' }), { target: { value: '25' } });

      expect(onChange).toHaveBeenCalledTimes(1);
      expect(onChange).toHaveBeenCalledWith({ type, count: 25, seed: 7 });
    }
  );

  it.each(['random', 'random edges'] as const)('stores %s count 1000 when the entered count is 5000', (type) => {
    const onChange = jest.fn();
    render(
      <NodeGraphEditor
        onChange={onChange}
        query={{ refId: 'A', scenarioId: TestDataQueryType.NodeGraph, nodes: { type, count: 10, seed: 7 } }}
      />
    );

    fireEvent.change(screen.getByRole('spinbutton', { name: 'Count' }), { target: { value: '5000' } });

    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith({ type, count: MAX_NODE_GRAPH_NODES, seed: 7 });
  });

  it.each(['random', 'random edges'] as const)(
    'stores %s count 1000 when the entered count is past the safe integer range',
    (type) => {
      const onChange = jest.fn();
      render(
        <NodeGraphEditor
          onChange={onChange}
          query={{ refId: 'A', scenarioId: TestDataQueryType.NodeGraph, nodes: { type, count: 10, seed: 7 } }}
        />
      );

      fireEvent.change(screen.getByRole('spinbutton', { name: 'Count' }), { target: { value: '9007199254740993' } });

      expect(onChange).toHaveBeenCalledTimes(1);
      expect(onChange).toHaveBeenCalledWith({ type, count: MAX_NODE_GRAPH_NODES, seed: 7 });
    }
  );
});
