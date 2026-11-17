// Test with local CSV files
import fs from 'fs';

import { MutableDataFrame } from '../dataframe/MutableDataFrame';
import { getDataFrameRow, toDataFrameDTO } from '../dataframe/processDataFrame';
import { getDisplayProcessor, getRawDisplayProcessor } from '../field/displayProcessor';
import { applyRawFieldOverrides } from '../field/fieldOverrides';
import { createTheme } from '../themes/createTheme';
import { FieldType } from '../types/dataFrame';
import { MappingType } from '../types/valueMapping';

import { CSVHeaderStyle, readCSV, toCSV } from './csv';

describe('read csv', () => {
  it('should get X and y', () => {
    const text = ',1\n2,3,4\n5,6\n,,,7';
    const data = readCSV(text);
    expect(data.length).toBe(1);

    const series = data[0];
    expect(series.fields.length).toBe(4);

    const rows = 4;
    expect(series.length).toBe(rows);

    // Make sure everything is padded properly
    for (const field of series.fields) {
      expect(field.values.length).toBe(rows);
    }

    const dto = toDataFrameDTO(series);
    expect(dto).toMatchSnapshot();
  });

  it('should read single string OK', () => {
    const text = 'a,b,c';
    const data = readCSV(text);
    expect(data.length).toBe(1);

    const series = data[0];
    expect(series.fields.length).toBe(3);
    expect(series.length).toBe(0);

    expect(series.fields[0].name).toEqual('a');
    expect(series.fields[1].name).toEqual('b');
    expect(series.fields[2].name).toEqual('c');
  });

  it('should read csv from local file system', () => {
    const path = __dirname + '/testdata/simple.csv';
    expect(fs.existsSync(path)).toBeTruthy();

    const csv = fs.readFileSync(path, 'utf8');
    const data = readCSV(csv);
    expect(data.length).toBe(1);
    expect(toDataFrameDTO(data[0])).toMatchSnapshot();
  });

  it('should read csv with headers', () => {
    const path = __dirname + '/testdata/withHeaders.csv';
    expect(fs.existsSync(path)).toBeTruthy();

    const csv = fs.readFileSync(path, 'utf8');
    const data = readCSV(csv);
    expect(data.length).toBe(1);
    expect(toDataFrameDTO(data[0])).toMatchSnapshot();
  });
});

function norm(csv: string): string {
  return csv.trim().replace(/[\r]/g, '');
}

describe('write csv', () => {
  it('should write the same CSV that we read', () => {
    const firstRow = [10, 'this "has quotes" inside', true];
    const path = __dirname + '/testdata/roundtrip.csv';
    const csv = fs.readFileSync(path, 'utf8');
    const data = readCSV(csv);
    const out = toCSV(data, { headerStyle: CSVHeaderStyle.full });
    expect(data.length).toBe(1);
    expect(getDataFrameRow(data[0], 0)).toEqual(firstRow);
    expect(data[0].fields.length).toBe(3);
    expect(norm(out)).toBe(norm(csv));

    // Keep the name even without special formatting
    const again = readCSV(out);
    const shorter = toCSV(again, { headerStyle: CSVHeaderStyle.name });

    const f = readCSV(shorter);
    const fields = f[0].fields;
    expect(fields.length).toBe(3);
    expect(getDataFrameRow(f[0], 0)).toEqual(firstRow);
    expect(fields.map((f) => f.name).join(',')).toEqual('a,b,c'); // the names
  });

  it('should add Excel header given config', () => {
    const dataFrame = new MutableDataFrame({
      fields: [
        { name: 'Time', values: [1598784913123, 1598784914123] },
        { name: 'Value', values: ['1234', '5678'] },
      ],
    });

    const csv = toCSV([dataFrame], { useExcelHeader: true });
    expect(csv).toMatchInlineSnapshot(`
      "sep=,
      "Time","Value"
      1598784913123,1234
      1598784914123,5678"
    `);
  });
});

describe('DataFrame to CSV', () => {
  it('should escape double quotes in the field names', () => {
    const dataFrame = new MutableDataFrame({
      fields: [
        { name: 'Time', values: [1589455688623] },
        // As we have traceId in message already this will shadow it.
        {
          name: 'Value',
          values: ['1234'],
          labels: {
            label1: 'value1',
            label2: 'value1',
          },
        },
      ],
    });

    const csv = toCSV([dataFrame]);
    expect(csv).toMatchInlineSnapshot(`
      ""Time","{label1=""value1"", label2=""value1""}"
      1589455688623,1234"
    `);
  });

  it('should use field display processor if exists', () => {
    const dataFrame = new MutableDataFrame({
      fields: [
        { name: 'Time', values: [1589455688623] },
        {
          name: 'Value',
          values: [1589455688623],
          config: {
            unit: 'dateTimeAsIso',
          },
        },
      ],
    });

    dataFrame.fields[1].display = getDisplayProcessor({
      field: dataFrame.fields[1],
      timeZone: 'utc',
      theme: createTheme(),
    });

    const csv = toCSV([dataFrame]);
    expect(csv).toMatchInlineSnapshot(`
      ""Time","Value"
      1589455688623,2020-05-14 11:28:08"
    `);
  });

  it('should handle field type frame', () => {
    const dataFrame = new MutableDataFrame({
      fields: [
        { name: 'Time', values: [1589455688623, 1589455692345] },
        {
          name: 'Value',
          type: FieldType.frame,
          values: [{ value: '1234' }, { value: '0' }],
        },
      ],
    });

    const csv = toCSV([dataFrame]);
    expect(csv).toMatchInlineSnapshot(`
      ""Time","Value"
      1589455688623,1234
      1589455692345,0"
    `);
  });

  it('should handle field type other', () => {
    const dataFrame = new MutableDataFrame({
      fields: [
        { name: 'Time', values: [1589455688623, 1589455692345] },
        {
          name: 'Value',
          type: FieldType.other,
          values: [{ text: 'value1' }, { text: 'value2' }],
        },
      ],
    });

    const csv = toCSV([dataFrame]);
    expect(csv).toMatchInlineSnapshot(`
      ""Time","Value"
      1589455688623,"{""text"":""value1""}"
      1589455692345,"{""text"":""value2""}""
    `);
  });

  it('should flatten nested frame rows', () => {
    const nestedFrame = {
      fields: [
        { name: 'Alarm Name', type: FieldType.string, values: ['ForwardPowerlow', 'PowerFoldback'], config: {} },
        { name: 'dateRange1', type: FieldType.number, values: [1, 0], config: {} },
        { name: 'dateRange2', type: FieldType.number, values: [3, 2], config: {} },
        { name: 'dateRange3', type: FieldType.number, values: [4, 4], config: {} },
      ],
      length: 2,
    };

    const dataFrame = new MutableDataFrame({
      fields: [
        { name: 'Alarm Category', type: FieldType.string, values: ['Base Station Alarm'] },
        { name: '__nestedFrames', type: FieldType.nestedFrames, values: [[nestedFrame]] },
      ],
    });

    const csv = toCSV([dataFrame]);
    expect(csv).toMatchInlineSnapshot(`
      ""Alarm Category","Alarm Name","dateRange1","dateRange2","dateRange3"
      Base Station Alarm,ForwardPowerlow,1,3,4
      Base Station Alarm,PowerFoldback,0,2,4"
    `);
  });

  it('should handle null values', () => {
    const dataFrame = new MutableDataFrame({
      fields: [
        { name: 'Time', values: [1589455688623] },
        {
          name: 'Value',
          type: FieldType.other,
          values: [null],
        },
      ],
    });

    const csv = toCSV([dataFrame]);
    expect(csv).toMatchInlineSnapshot(`
      ""Time","Value"
      1589455688623,"
    `);
  });
});

// Spreadsheet formula triggers. A cell whose text starts with one of these is evaluated when a
// spreadsheet imports the file (LibreOffice Calc treats a leading "=" as a formula by default,
// including when the CSV field was quoted). Quoting the field is not neutralization: the parsed
// cell text is what the spreadsheet sees.
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

describe('formula text in CSV cells', () => {
  const payloads = ['=1+1', '+1+1', '-2+3', '@SUM(1+1)', '\t=1+1', '=1,2', '=1"2', '=1\n2', '-5'];

  it.each(payloads)('neutralizes a string cell %j', (payload) => {
    const frame = new MutableDataFrame({
      fields: [
        { name: 'label', type: FieldType.string, values: ['keep'] },
        { name: 'note', type: FieldType.string, values: [payload] },
      ],
    });

    const csv = toCSV([frame], { delimiter: ',' });
    const rows = parseCsvRecords(csv, ',');

    expect(rows[0]).toEqual(['label', 'note']);
    expect(rows[1][0]).toBe('keep');
    expectFormulaTextNeutralized(rows[1][1], payload);
  });

  it('leaves ordinary text and numbers unchanged', () => {
    const frame = new MutableDataFrame({
      fields: [
        { name: 'label', type: FieldType.string, values: ['hello', 'a=b', '1+2'] },
        { name: 'n', type: FieldType.number, values: [42, 0, 7] },
      ],
    });

    const csv = toCSV([frame], { delimiter: ',' });
    expect(parseCsvRecords(csv, ',')).toEqual([
      ['label', 'n'],
      ['hello', '42'],
      ['a=b', '0'],
      ['1+2', '7'],
    ]);
  });

  it('neutralizes a numeric value whose text starts with a minus sign', () => {
    const frame = new MutableDataFrame({
      fields: [{ name: 'n', type: FieldType.number, values: [-5] }],
    });

    const cell = parseCsvRecords(toCSV([frame], { delimiter: ',' }), ',')[1][0];
    expectFormulaTextNeutralized(cell, '-5');
  });

  it('neutralizes formula text produced by a display processor', () => {
    const frame = new MutableDataFrame({
      fields: [{ name: 'note', type: FieldType.string, values: ['=1+1'], config: {} }],
    });
    frame.fields[0].display = getDisplayProcessor({ field: frame.fields[0], theme: createTheme() });

    const cell = parseCsvRecords(toCSV([frame], { delimiter: ',' }), ',')[1][0];
    expectFormulaTextNeutralized(cell, '=1+1');
  });

  it('neutralizes formula text produced by the raw display processor', () => {
    const frame = new MutableDataFrame({
      fields: [{ name: 'note', type: FieldType.string, values: ['=1+1'], config: {} }],
    });
    const [processed] = applyRawFieldOverrides([frame]);

    const cell = parseCsvRecords(toCSV([processed], { delimiter: ',' }), ',')[1][0];
    expectFormulaTextNeutralized(cell, '=1+1');
  });

  it('neutralizes formula text that a value mapping substitutes for a safe value', () => {
    const frame = new MutableDataFrame({
      fields: [
        {
          name: 'note',
          type: FieldType.string,
          values: ['visible'],
          config: {
            mappings: [
              {
                type: MappingType.ValueToText,
                options: { visible: { text: '=1+1' } },
              },
            ],
          },
        },
      ],
    });
    frame.fields[0].display = getDisplayProcessor({ field: frame.fields[0], theme: createTheme() });

    const cell = parseCsvRecords(toCSV([frame], { delimiter: ',' }), ',')[1][0];
    expectFormulaTextNeutralized(cell, '=1+1');
    expect(cell).not.toBe('visible');
  });

  it('neutralizes a column name and a configured display name', () => {
    const named = new MutableDataFrame({
      fields: [{ name: '=1+1', type: FieldType.string, values: ['keep'] }],
    });
    const namedCell = parseCsvRecords(toCSV([named], { delimiter: ',' }), ',')[0][0];
    expectFormulaTextNeutralized(namedCell, '=1+1');

    const titled = new MutableDataFrame({
      fields: [
        {
          name: 'note',
          type: FieldType.string,
          values: ['keep'],
          config: { displayName: '=1+1' },
        },
      ],
    });
    const titledCell = parseCsvRecords(toCSV([titled], { delimiter: ',' }), ',')[0][0];
    expectFormulaTextNeutralized(titledCell, '=1+1');
  });

  it('neutralizes a later column name in the full header', () => {
    const frame = new MutableDataFrame({
      fields: [
        { name: 'label', type: FieldType.string, values: ['keep'] },
        { name: '=1+1', type: FieldType.string, values: ['keep'] },
      ],
    });

    const rows = parseCsvRecords(toCSV([frame], { delimiter: ',', headerStyle: CSVHeaderStyle.full }), ',');
    const nameRow = rows.find((row) => row[0]?.startsWith('#name#'));
    expect(nameRow).toBeDefined();
    expectFormulaTextNeutralized(nameRow![1], '=1+1');
  });

  it('neutralizes a nested frame cell and a frame-typed cell', () => {
    const nestedFrame = {
      fields: [{ name: 'Alarm Name', type: FieldType.string, values: ['=1+1'], config: {} }],
      length: 1,
    };
    const nested = new MutableDataFrame({
      fields: [
        { name: 'Alarm Category', type: FieldType.string, values: ['keep'] },
        { name: '__nestedFrames', type: FieldType.nestedFrames, values: [[nestedFrame]] },
      ],
    });
    const nestedRows = parseCsvRecords(toCSV([nested], { delimiter: ',' }), ',');
    expectFormulaTextNeutralized(nestedRows[1][1], '=1+1');

    const framed = new MutableDataFrame({
      fields: [
        {
          name: 'Value',
          type: FieldType.frame,
          values: [{ value: '=1+1' }],
        },
      ],
    });
    const framedCell = parseCsvRecords(toCSV([framed], { delimiter: ',' }), ',')[1][0];
    expectFormulaTextNeutralized(framedCell, '=1+1');
  });
});
