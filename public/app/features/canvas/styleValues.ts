import { Align, VAlign } from './types';

// Element data comes from saved panel JSON and field config, and is written into emotion
// stylesheets, so each value must be a single CSS token that cannot start another declaration.
const HEX_COLOR = /^#(?:[0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})$/i;
const FUNCTION_COLOR = /^(?:rgba?|hsla?)\([\d\s.,%+\-/]*\)$/i;
const NAMED_COLOR = /^[a-z]+$/i;
const NUMBER = /^-?\d+(?:\.\d+)?$/;

const alignValues = Object.values(Align);
const valignValues = Object.values(VAlign);

export function cssColor(value: unknown): string | undefined {
  if (typeof value !== 'string') {
    return undefined;
  }
  const color = value.trim();
  if (HEX_COLOR.test(color) || FUNCTION_COLOR.test(color) || NAMED_COLOR.test(color)) {
    return color;
  }
  return undefined;
}

export function cssNumber(value: unknown): number | undefined {
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : undefined;
  }
  if (typeof value === 'string' && NUMBER.test(value.trim())) {
    return Number(value);
  }
  return undefined;
}

export function cssPixels(value: unknown): string | undefined {
  const n = cssNumber(value);
  return n === undefined ? undefined : `${n}px`;
}

export function cssTextAlign(value: unknown): Align | undefined {
  return alignValues.find((align) => align === value);
}

export function cssVerticalAlign(value: unknown): VAlign | undefined {
  return valignValues.find((valign) => valign === value);
}
