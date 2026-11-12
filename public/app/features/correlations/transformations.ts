import logfmt from 'logfmt';

import { type ScopedVars, type DataLinkTransformationConfig, SupportedTransformationType } from '@grafana/data';
import { safeStringifyValue } from 'app/core/utils/explore';

import { findTransformationRegexMatches } from './transformationRegex';

export const getTransformationVars = (
  transformation: DataLinkTransformationConfig,
  fieldValue: string,
  fieldName: string
): ScopedVars => {
  let transformationScopedVars: ScopedVars = {};
  let transformVal: { [key: string]: string | boolean | null | undefined } = {};
  if (transformation.type === SupportedTransformationType.Regex && transformation.expression) {
    const stringFieldVal = typeof fieldValue === 'string' ? fieldValue : safeStringifyValue(fieldValue);

    const matches = findTransformationRegexMatches(transformation.expression, stringFieldVal) ?? [];
    for (const match of matches) {
      if (match.groups) {
        transformVal = match.groups;
      } else {
        transformVal[transformation.mapValue || fieldName] = match.firstGroup || match.value;
      }
    }
  } else if (transformation.type === SupportedTransformationType.Logfmt && fieldValue !== undefined) {
    transformVal = logfmt.parse(fieldValue);
  }

  Object.keys(transformVal).forEach((key) => {
    const transformValString =
      typeof transformVal[key] === 'string' ? transformVal[key] : safeStringifyValue(transformVal[key]);
    transformationScopedVars[key] = { value: transformValString };
  });

  return transformationScopedVars;
};
