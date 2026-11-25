import { css } from '@emotion/css';

import { TextLink, Tooltip } from '@grafana/ui';

import { type Annotation, annotationLabels } from '../utils/constants';
import { getExternalLinkHref } from '../utils/url';

import { DetailsField } from './DetailsField';
import { Tokenize } from './Tokenize';
import { Well } from './Well';

const wellableAnnotationKeys = ['message', 'description'];

interface Props {
  annotationKey: string;
  value: string;
  valueLink?: string;
}

export const AnnotationDetailsField = ({ annotationKey, value, valueLink }: Props) => {
  const annotation = annotationKey as Annotation;
  const label = annotationLabels[annotation] ? (
    <Tooltip content={annotationKey} placement="top" theme="info">
      <span>{annotationLabels[annotation]}</span>
    </Tooltip>
  ) : (
    annotationKey
  );

  return (
    <DetailsField label={label} horizontal={true} childrenWrapperClassName={styles.value}>
      <AnnotationValue annotationKey={annotationKey} value={value} valueLink={valueLink} />
    </DetailsField>
  );
};

const AnnotationValue = ({ annotationKey, value, valueLink }: Props) => {
  const needsWell = wellableAnnotationKeys.includes(annotationKey);
  const externalHref = value && value.startsWith('http') ? getExternalLinkHref(value) : undefined;

  const tokenizeValue = <Tokenize input={value} delimiter={['{{', '}}']} />;

  if (valueLink) {
    return (
      <TextLink href={valueLink} external>
        {value}
      </TextLink>
    );
  }

  if (needsWell) {
    return <Well className={styles.well}>{tokenizeValue}</Well>;
  }

  if (externalHref) {
    return (
      <TextLink href={externalHref} external>
        {value}
      </TextLink>
    );
  }

  return <>{tokenizeValue}</>;
};

const styles = {
  value: css({
    minWidth: 0,
    overflowWrap: 'anywhere',
  }),
  well: css({
    wordBreak: 'break-word',
  }),
};
