import { fireEvent, render, screen } from '@testing-library/react';

import { CSVContentEditor } from './components/CSVContentEditor';
import { TestDataQueryType, type TestDataDataQuery } from './dataquery';

jest.mock('@grafana/ui', () => {
  const actual = jest.requireActual('@grafana/ui');
  return {
    ...actual,
    // Stand-in for CodeEditor.onBlur, which calls props.onBlur with the current
    // editor value (packages/grafana-ui/src/components/Monaco/CodeEditor.tsx).
    // Monaco does not finish loading under Jest, so the textarea invokes that
    // same callback with the text the editor would save.
    CodeEditor: ({ value, onBlur }: { value: string; onBlur?: (next: string) => void }) => (
      <textarea aria-label="CSV content" defaultValue={value} onBlur={(event) => onBlur?.(event.currentTarget.value)} />
    ),
  };
});

/**
 * Same maximum as testdataStepsCsvLimit.test.ts. The steps editor must not hand the
 * parent query model a csvContent value with more non-empty lines than this.
 * CSV Content uses the same component but is parsed into columns on the
 * server, so this cap is only required for the steps scenario.
 */
const MAX_STEP_LINES = 100;

function csvWithLines(count: number): string {
  return Array.from({ length: count }, (_, index) => `s${index}`).join('\n');
}

function nonEmptyLineCount(csv: string): number {
  return csv.split('\n').filter((line) => line.trim().length > 0).length;
}

function blurCsv(query: TestDataDataQuery, next: string) {
  const onChange = jest.fn();
  render(<CSVContentEditor onChange={onChange} query={query} ds={{} as never} />);
  const editor = screen.getByRole('textbox', { name: 'CSV content' });
  fireEvent.change(editor, { target: { value: next } });
  fireEvent.blur(editor);
  return onChange;
}

describe('CSVContentEditor steps line cap', () => {
  it('stores a short steps list unchanged when the editor blurs', () => {
    const query: TestDataDataQuery = {
      refId: 'A',
      scenarioId: TestDataQueryType.Steps,
      csvContent: '',
    };
    const onChange = blurCsv(query, 'a\nb\nc\n');

    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith({ ...query, csvContent: 'a\nb\nc\n' });
  });

  it('does not publish steps csvContent above the maximum line count', () => {
    const query: TestDataDataQuery = {
      refId: 'A',
      scenarioId: TestDataQueryType.Steps,
      csvContent: 'a\nb\n',
    };
    const oversized = csvWithLines(MAX_STEP_LINES + 1);
    const onChange = blurCsv(query, oversized);

    const published = onChange.mock.calls.map((call) => call[0].csvContent as string);
    expect(published.every((csv) => nonEmptyLineCount(csv) <= MAX_STEP_LINES)).toBe(true);
    expect(published).not.toContain(oversized);
  });

  it('still stores CSV Content rows that are past the steps line maximum', () => {
    const rows = csvWithLines(MAX_STEP_LINES + 1);
    const query: TestDataDataQuery = {
      refId: 'A',
      scenarioId: TestDataQueryType.CSVContent,
      csvContent: '',
    };
    const onChange = blurCsv(query, rows);

    expect(onChange).toHaveBeenCalledWith({ ...query, csvContent: rows });
  });
});
