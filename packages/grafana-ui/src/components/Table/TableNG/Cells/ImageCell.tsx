import { css } from '@emotion/css';
import { useState } from 'react';

import { textUtil } from '@grafana/data';

import { TableCellDisplayMode } from '../../types';
import { MaybeWrapWithLink } from '../components/MaybeWrapWithLink';
import { type ImageCellProps, type TableCellStyles } from '../types';

export const ImageCell = ({ cellOptions, field, value, rowIdx }: ImageCellProps) => {
  const [error, setError] = useState(false);
  const { text } = field.display!(value);
  const { alt, title } =
    cellOptions.type === TableCellDisplayMode.Image ? cellOptions : { alt: undefined, title: undefined };

  if (!text) {
    return null;
  }

  const src = textUtil.sanitizeImageUrl(text);

  return (
    <MaybeWrapWithLink field={field} rowIdx={rowIdx}>
      {error || !src ? (alt ?? text) : <img alt={alt} src={src} title={title} onError={() => setError(true)} />}
    </MaybeWrapWithLink>
  );
};

const styles = css({
  '&, a, img': {
    width: '100%',
    height: '100%',
  },
  img: {
    objectFit: 'contain',
  },
});

export const getStyles: TableCellStyles = () => styles;
