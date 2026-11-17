import saveAs from 'file-saver';

import {
  dataFrameFromJSON,
  type DataFrameJSON,
  dateTimeFormat,
  FieldType,
  type LogRowModel,
  LogsMetaKind,
} from '@grafana/data';
import { createLogRow } from 'app/features/logs/components/mocks/logRow';

import { downloadAsJson, downloadDataFrameAsCsv, downloadLogsModelAsTxt } from './download';

jest.mock('file-saver', () => jest.fn());

describe('inspector download', () => {
  beforeEach(() => {
    jest.clearAllMocks();
    jest.useFakeTimers({ now: new Date(1400000000000) });
  });
  afterEach(() => {
    jest.useRealTimers();
  });

  describe('downloadDataFrameAsCsv', () => {
    const json: DataFrameJSON = {
      schema: {
        fields: [
          { name: 'time', type: FieldType.time },
          { name: 'name', type: FieldType.string },
          { name: 'value', type: FieldType.number },
        ],
      },
      data: {
        values: [[100], ['Åäö中文العربية'], [1]],
      },
    };

    it.each([[dataFrameFromJSON(json), 'test', '"time","name","value"\r\n100,Åäö中文العربية,1']])(
      'should, when logsModel is %s and title is %s, resolve in %s',
      async (dataFrame, title, expected) => {
        downloadDataFrameAsCsv(dataFrame, title);
        const call = jest.mocked(saveAs).mock.calls[0];
        const blob = call[0];
        const filename = call[1];
        const text = typeof blob === 'string' ? blob : await blob.text();

        // By default the BOM character should not be included
        expect(blob instanceof Blob ? await getBomType(blob) : undefined).toBeUndefined();
        expect(text).toEqual(expected);
        expect(filename).toEqual(`${title}-data-${dateTimeFormat(1400000000000)}.csv`);
      }
    );

    it('should use \t as the delimiter and the file should be utf16le if excelCompatibilityMode is true', async () => {
      downloadDataFrameAsCsv(dataFrameFromJSON(json), 'test', undefined, undefined, true);

      const call = jest.mocked(saveAs).mock.calls[0];
      const blob = call[0];
      const filename = call[1];
      const text = typeof blob === 'string' ? blob : await blob.text();

      if (blob instanceof Blob) {
        expect(await getBomType(blob)).toBe('utf-16le');
        expect(blob.type).toBe('text/csv;charset=utf-16le');
      }
      expect(text).toEqual('"time"\t"name"\t"value"\r\n100\tÅäö中文العربية\t1');
      expect(filename).toEqual(`test-data-${dateTimeFormat(1400000000000)}.csv`);
      expect.assertions(4);
    });

    it('end with a new line if asked', async () => {
      downloadDataFrameAsCsv(dataFrameFromJSON(json), 'test', undefined, undefined, false, true);

      const call = jest.mocked(saveAs).mock.calls[0];
      const blob = call[0];
      const text = typeof blob === 'string' ? blob : await blob.text();

      expect(text).toEqual('"time","name","value"\r\n100,Åäö中文العربية,1\r\n');
    });

    // Inspect data download and the logs panel CSV download both call this function.
    it.each(['=1+1', '+1+1', '-2+3', '@SUM(1+1)', '\t=1+1'])(
      'neutralizes formula text %j in the CSV file',
      async (payload) => {
        const frame = dataFrameFromJSON({
          schema: {
            fields: [
              { name: 'label', type: FieldType.string },
              { name: 'note', type: FieldType.string },
            ],
          },
          data: { values: [['keep'], [payload]] },
        });

        downloadDataFrameAsCsv(frame, 'panel');
        const text = await blobText(jest.mocked(saveAs).mock.calls[0][0]);
        const rows = parseCsvRecords(text, ',');

        expect(rows[1][0]).toBe('keep');
        expectFormulaTextNeutralized(rows[1][1], payload);
      }
    );

    it('neutralizes formula text in the Excel-compatible file bytes', async () => {
      const frame = dataFrameFromJSON({
        schema: {
          fields: [{ name: 'note', type: FieldType.string }],
        },
        data: { values: [['=1+1']] },
      });

      downloadDataFrameAsCsv(frame, 'panel', undefined, undefined, true);
      const blob = jest.mocked(saveAs).mock.calls[0][0];
      expect(blob).toBeInstanceOf(Blob);
      const bytes = new Uint8Array(await (blob as Blob).arrayBuffer());
      expect(bytes[0]).toBe(0xff);
      expect(bytes[1]).toBe(0xfe);

      const text = decodeUtf16Le(bytes);
      const cell = parseCsvRecords(text, '\t')[1][0];
      expectFormulaTextNeutralized(cell, '=1+1');
    });
  });

  describe('downloadAsJson', () => {
    it.each([
      ['foo', 'test', '"foo"'],
      [1, 'test', '1'],
      [{ foo: 'bar' }, 'test', '{"foo":"bar"}'],
    ])('should, when logsModel is %s and title is %s, resolve in %s', async (logsModel, title, expected) => {
      downloadAsJson(logsModel, title);
      const call = jest.mocked(saveAs).mock.calls[0];
      const blob = call[0];
      const filename = call[1];
      const text = typeof blob === 'string' ? blob : await blob.text();

      expect(text).toEqual(expected);
      expect(filename).toEqual(`${title}-${dateTimeFormat(1400000000000)}.json`);
    });
  });

  describe('downloadLogsModelAsTxt', () => {
    it.each([
      [{ meta: [], rows: [] }, 'test', ''],
      [
        { meta: [{ label: 'testLabel', value: 'testValue', kind: LogsMetaKind.String }], rows: [] },
        'test',
        'testLabel: "testValue"\n\n\n',
      ],
      [{ meta: [{ label: 'testLabel', value: 1, kind: LogsMetaKind.Number }], rows: [] }, 'test', 'testLabel: 1\n\n\n'],
      [
        {
          meta: [
            { label: 'testLabel', value: 1, kind: LogsMetaKind.String },
            { label: 'secondTestLabel', value: 2, kind: LogsMetaKind.String },
          ],
          rows: [],
        },
        'test',
        'testLabel: 1\nsecondTestLabel: 2\n\n\n',
      ],
      [
        {
          meta: [
            { label: 'testLabel', value: 1, kind: LogsMetaKind.String },
            { label: 'secondTestLabel', value: 2, kind: LogsMetaKind.String },
          ],
          rows: [{ timeEpochMs: 100, entry: 'testEntry' } as unknown as LogRowModel],
        },
        'test',
        `testLabel: 1\nsecondTestLabel: 2\n\n\n100\t1970-01-01T00:00:00.100Z\ttestEntry\n`,
      ],
    ])('should, when logsModel is %s and title is %s, resolve in %s', async (logsModel, title, expected) => {
      downloadLogsModelAsTxt(logsModel, title);
      const call = jest.mocked(saveAs).mock.calls[0];
      const blob = call[0];
      const filename = call[1];
      const text = typeof blob === 'string' ? blob : blob.size === 0 ? '' : await blob.text();

      expect(text).toEqual(expected);
      expect(filename).toEqual(`${title}-logs-${dateTimeFormat(1400000000000)}.txt`);
    });

    it('should, when title is empty, resolve in %s', async () => {
      downloadLogsModelAsTxt({ meta: [], rows: [] });
      const call = jest.mocked(saveAs).mock.calls[0];
      const filename = call[1];
      expect(filename).toEqual(`Logs-${dateTimeFormat(1400000000000)}.txt`);
    });

    it('should, when title is empty, resolve in %s', async () => {
      downloadLogsModelAsTxt({ meta: [], rows: [] });
      const call = jest.mocked(saveAs).mock.calls[0];
      const filename = call[1];
      expect(filename).toEqual(`Logs-${dateTimeFormat(1400000000000)}.txt`);
    });

    it('should should download selected fields', async () => {
      const logsModel = {
        meta: [],
        rows: [
          createLogRow({ timeEpochMs: 100, entry: 'testEntry', labels: { label: 'value', otherLabel: 'other value' } }),
        ],
      };
      downloadLogsModelAsTxt(logsModel, undefined, ['label', 'otherLabel']);
      const call = jest.mocked(saveAs).mock.calls[0];
      const blob = call[0];
      const text = typeof blob === 'string' ? blob : await blob.text();

      expect(text).toContain('value other value');
    });
  });
});

const FORMULA_TRIGGERS = ['=', '+', '-', '@', '\t'];

function parseCsvRecords(csv: string, delimiter: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = '';
  let quoted = false;

  for (let i = 0; i < csv.length; i++) {
    const char = csv[i];
    if (quoted) {
      if (char === '"') {
        if (csv[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          quoted = false;
        }
      } else {
        field += char;
      }
      continue;
    }
    if (char === '"') {
      quoted = true;
      continue;
    }
    if (char === delimiter) {
      row.push(field);
      field = '';
      continue;
    }
    if (char === '\n') {
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
      continue;
    }
    if (char === '\r') {
      continue;
    }
    field += char;
  }

  if (field.length > 0 || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

function expectFormulaTextNeutralized(cell: string, source: string) {
  expect(FORMULA_TRIGGERS).not.toContain(cell.charAt(0));
  expect(cell.endsWith(source)).toBe(true);
  expect(cell.length).toBeGreaterThan(source.length);
}

async function blobText(blob: Blob | string): Promise<string> {
  return typeof blob === 'string' ? blob : blob.text();
}

function decodeUtf16Le(bytes: Uint8Array): string {
  const start = bytes[0] === 0xff && bytes[1] === 0xfe ? 2 : 0;
  let text = '';
  for (let i = start; i + 1 < bytes.length; i += 2) {
    text += String.fromCharCode(bytes[i] | (bytes[i + 1] << 8));
  }
  return text;
}

async function getBomType(blob: Blob): Promise<'utf-8' | 'utf-16le' | undefined> {
  const reader = new FileReader();
  return new Promise((resolve, reject) => {
    reader.onload = (event: ProgressEvent<FileReader>) => {
      if (event.target?.result instanceof ArrayBuffer) {
        const arr = new Uint8Array(event.target.result);
        // UTF-8: EF BB BF
        if (arr.length >= 3 && arr[0] === 0xef && arr[1] === 0xbb && arr[2] === 0xbf) {
          resolve('utf-8');
          return;
        }
        // UTF-16 LE: FF FE
        if (arr.length >= 2 && arr[0] === 0xff && arr[1] === 0xfe) {
          resolve('utf-16le');
          return;
        }
        resolve(undefined);
      } else {
        reject(new Error('Unexpected FileReader result type'));
      }
    };
    reader.onerror = reject;
    reader.readAsArrayBuffer(blob.slice(0, 3)); // Read first 3 bytes (covers UTF-8 and UTF-16LE)
  });
}
