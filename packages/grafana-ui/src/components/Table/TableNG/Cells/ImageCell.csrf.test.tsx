import { render } from '@testing-library/react';

import { createTheme, type Field, FieldType, getDisplayProcessor } from '@grafana/data';
import { credentialedResourceUrls } from 'test/credentialedResourceUrls';

import { TableCellDisplayMode } from '../../types';

import { ImageCell } from './ImageCell';

const theme = createTheme();

function imageField(value: string): Field<string> {
  const field: Field<string> = {
    name: 'image',
    type: FieldType.string,
    values: [value],
    config: { custom: { cellOptions: { type: TableCellDisplayMode.Image } } },
  };
  field.display = getDisplayProcessor({ field, theme });
  return field;
}

describe('table image cells', () => {
  it.each(['/logout', '/profile/switch-org/2', './logout'])(
    'does not point an img at a same-origin path from the query: %s',
    (value) => {
      const field = imageField(value);
      const { container } = render(
        <ImageCell
          cellOptions={{ type: TableCellDisplayMode.Image }}
          field={field}
          value={value}
          rowIdx={0}
        />
      );
      expect(credentialedResourceUrls(container.innerHTML)).toEqual([]);
    }
  );

  it('still renders an external image', () => {
    const value = 'https://example.com/cat.png';
    const field = imageField(value);
    const { container } = render(
      <ImageCell cellOptions={{ type: TableCellDisplayMode.Image }} field={field} value={value} rowIdx={0} />
    );
    expect(container.querySelector('img')).toHaveAttribute('src', value);
    expect(credentialedResourceUrls(container.innerHTML)).toEqual([]);
  });
});
