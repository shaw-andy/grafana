import { render } from '@testing-library/react';

import { createDataFrame, createTheme, type Field, FieldType, getDisplayProcessor } from '@grafana/data';
import { credentialedResourceUrls } from 'test/credentialedResourceUrls';

import { type TableCellOptions, TableCellDisplayMode } from '../../types';
import { getCellOptions } from '../utils';

import { getCellRenderer } from './renderers';

const theme = createTheme();

function markdownField(value: string): Field<string> {
  const field: Field<string> = {
    name: 'message',
    type: FieldType.string,
    values: [value],
    config: {
      custom: {
        cellOptions: { type: TableCellDisplayMode.Markdown } satisfies TableCellOptions,
      },
    },
  };
  field.display = getDisplayProcessor({ field, theme });
  return field;
}

function renderMarkdownCell(value: string, disableSanitizeHtml: boolean) {
  const field = markdownField(value);
  const cellOptions = getCellOptions(field);
  const Cell = getCellRenderer(field, cellOptions);
  return render(
    <Cell
      field={field}
      rowIdx={0}
      value={field.values[0]}
      cellOptions={cellOptions}
      frame={createDataFrame({ fields: [field] })}
      height={40}
      width={240}
      theme={theme}
      cellInspect={false}
      showFilters={false}
      disableSanitizeHtml={disableSanitizeHtml}
      getTextColorForBackground={() => '#000000'}
    />
  );
}

const cellValues = [
  'visible\n\n![alt](/logout)',
  'visible\n\n![alt](/profile/switch-org/2)',
  'visible\n\n<img src="/logout">',
  'visible\n\n<img src="&#47;profile/switch-org/2">',
  'visible\n\n<audio src="/logout"></audio>',
  'visible\n\n<video poster="/logout"></video>',
  'visible\n\n<div style="background-image:url(/logout)"></div>',
  'visible\n\n<iframe src="/logout"></iframe>',
  'visible\n\n<meta http-equiv="refresh" content="0;url=/logout">',
];

describe('table markdown cells', () => {
  it.each(cellValues)('does not request a credentialed URL when sanitization is on: %s', (value) => {
    const { container } = renderMarkdownCell(value, false);
    expect(credentialedResourceUrls(container.innerHTML)).toEqual([]);
    expect(container).toHaveTextContent('visible');
  });

  it.each(cellValues)('does not request a credentialed URL when disableSanitizeHtml is set: %s', (value) => {
    const { container } = renderMarkdownCell(value, true);
    expect(credentialedResourceUrls(container.innerHTML)).toEqual([]);
    expect(container).toHaveTextContent('visible');
  });
});
