import { css } from '@emotion/css';

import { TextLink, Tooltip } from '@grafana/ui';

import { type Annotation, annotationLabels } from '../utils/constants';
import { parseExternalAlertmanagerUrl } from '../utils/url';

import { DetailsField } from './DetailsField';
import { Tokenize } from './Tokenize';
import { Well } from './Well';

const wellableAnnotationKeys = ['message', 'description'];

interface Props {
  annotationKey: string;
  value: string;
  valueLink?: string;
  /** Only render the value as a link when it points outside of Grafana, for annotations that users cannot be trusted with. */
  externalLinksOnly?: boolean;
}

export const AnnotationDetailsField = ({ annotationKey, value, valueLink, externalLinksOnly }: Props) => {
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
      <AnnotationValue
        annotationKey={annotationKey}
        value={value}
        valueLink={valueLink}
        externalLinksOnly={externalLinksOnly}
      />
    </DetailsField>
  );
};

const AnnotationValue = ({ annotationKey, value, valueLink, externalLinksOnly }: Props) => {
  const needsWell = wellableAnnotationKeys.includes(annotationKey);
  const externalLink = externalLinksOnly ? parseExternalAlertmanagerUrl(value)?.href : value;
  const needsExternalLink = value && value.startsWith('http') && externalLink;

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

  if (needsExternalLink) {
    return (
      <TextLink href={externalLink} external>
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
