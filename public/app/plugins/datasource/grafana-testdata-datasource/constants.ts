import {
  type CSVWave,
  type ExemplarLabel,
  type PulseWaveQuery,
  type TestDataDataQuery,
  TestDataQueryType,
} from './dataquery';

export const defaultPulseQuery: PulseWaveQuery = {
  timeStep: 60,
  onCount: 3,
  onValue: 2,
  offCount: 3,
  offValue: 1,
};

export const defaultCSVWaveQuery: CSVWave[] = [
  {
    timeStep: 60,
    valuesCSV: '0,0,2,2,1,1',
  },
];

export const defaultExemplarLabels: ExemplarLabel[] = [
  {
    name: 'traceID',
    length: 16,
  },
];

export const defaultQuery: TestDataDataQuery = {
  scenarioId: TestDataQueryType.RandomWalk,
  refId: '',
};

export const DEFAULT_TRACE_SPAN_COUNT = 10;
// Trace spans are built on the browser main thread when the panel loads.
export const MAX_TRACE_SPAN_COUNT = 100;

// @todo export from logs model
export const DATAPLANE_LABEL_TYPES_NAME = 'labelTypes';
