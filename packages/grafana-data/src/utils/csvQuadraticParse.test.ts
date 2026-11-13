import { CSVReader, readCSV } from './csv';

// Papa.parse searches for the delimiter with String#indexOf. On quoted rows that
// never contain the delimiter, versions before 5.7.1 repeat that search from the
// current row to the end of the buffer. Counting characters examined on the CSV
// string itself distinguishes that quadratic scan from a linear parse.
function charsScannedForDelimiter(csv: string, delimiter: string, parse: () => void): number {
  const originalIndexOf = String.prototype.indexOf;
  let scanned = 0;

  String.prototype.indexOf = function (this: string, search: string, position?: number): number {
    if (search === delimiter && this.length === csv.length) {
      const start = position ?? 0;
      scanned += Math.max(0, this.length - start);
    }
    return originalIndexOf.call(this, search, position as number);
  };

  try {
    parse();
  } finally {
    String.prototype.indexOf = originalIndexOf;
  }

  return scanned;
}

function quotedColumn(rows: number): string {
  return '"a"\n'.repeat(rows);
}

const ROWS = 4000;
// A fixed parser walks the buffer a handful of times. The vulnerable parser walks
// a suffix once per row, which is hundreds of times the input length at ROWS.
const MAX_LINEAR_PASSES = 8;

describe('quoted CSV delimiter scans', () => {
  it('readCSV parses a delimiter-free quoted column without a full-buffer delimiter scan per row', () => {
    const csv = quotedColumn(ROWS);
    const scanned = charsScannedForDelimiter(csv, ',', () => {
      const frame = readCSV(csv)[0];
      expect(frame.fields).toHaveLength(1);
      expect(frame.fields[0].name).toBe('a');
      expect(frame.fields[0].values).toHaveLength(ROWS - 1);
      expect(frame.fields[0].values[0]).toBe('a');
      expect(frame.fields[0].values[ROWS - 2]).toBe('a');
    });

    expect(scanned).toBeLessThanOrEqual(csv.length * MAX_LINEAR_PASSES);
  });

  it('CSVReader.readCSV parses a delimiter-free quoted column without a full-buffer delimiter scan per row', () => {
    const csv = quotedColumn(ROWS);
    const scanned = charsScannedForDelimiter(csv, ',', () => {
      const frame = new CSVReader().readCSV(csv)[0];
      expect(frame.fields).toHaveLength(1);
      expect(frame.fields[0].name).toBe('a');
      expect(frame.fields[0].values).toHaveLength(ROWS - 1);
      expect(frame.fields[0].values[0]).toBe('a');
      expect(frame.fields[0].values[ROWS - 2]).toBe('a');
    });

    expect(scanned).toBeLessThanOrEqual(csv.length * MAX_LINEAR_PASSES);
  });

  it('readCSV keeps delimiter scans linear when a header contains the delimiter and the body does not', () => {
    const csv = 'key,value\n' + quotedColumn(ROWS);
    const scanned = charsScannedForDelimiter(csv, ',', () => {
      const frame = readCSV(csv)[0];
      expect(frame.fields[0].name).toBe('key');
      expect(frame.fields[1].name).toBe('value');
      expect(frame.fields[0].values).toHaveLength(ROWS);
      expect(frame.fields[0].values[0]).toBe('a');
      expect(frame.fields[0].values[ROWS - 1]).toBe('a');
    });

    expect(scanned).toBeLessThanOrEqual(csv.length * MAX_LINEAR_PASSES);
  });

  it('readCSV keeps delimiter scans linear when CSVConfig.delimiter is absent from the quoted input', () => {
    const csv = quotedColumn(ROWS);
    const scanned = charsScannedForDelimiter(csv, '|', () => {
      const frame = readCSV(csv, { config: { delimiter: '|' } })[0];
      expect(frame.fields).toHaveLength(1);
      expect(frame.fields[0].name).toBe('a');
      expect(frame.fields[0].values).toHaveLength(ROWS - 1);
      expect(frame.fields[0].values[0]).toBe('a');
      expect(frame.fields[0].values[ROWS - 2]).toBe('a');
    });

    expect(scanned).toBeLessThanOrEqual(csv.length * MAX_LINEAR_PASSES);
  });
});
