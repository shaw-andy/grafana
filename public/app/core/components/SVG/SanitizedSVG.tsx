import SVG, { type Props } from 'react-inlinesvg';

import { textUtil } from '@grafana/data';

import { svgStyleCleanup } from './utils';

type SanitizedSVGProps = Props & { cleanStyle?: boolean };

export const SanitizedSVG = (props: SanitizedSVGProps) => {
  const { cleanStyle, ...inlineSvgProps } = props;
  // The src is often saved with a dashboard, so the request must not carry the viewer's cookies
  return (
    <SVG
      {...inlineSvgProps}
      fetchOptions={{ ...inlineSvgProps.fetchOptions, credentials: 'omit' }}
      cacheRequests={true}
      preProcessor={cleanStyle ? getCleanSVGAndStyle : getCleanSVG}
    />
  );
};

let cache = new Map<string, string>();

function getCleanSVG(code: string): string {
  let clean = cache.get(code);
  if (!clean) {
    clean = textUtil.sanitizeSVGContent(code);
    cache.set(code, clean);
  }

  return clean;
}

function getCleanSVGAndStyle(code: string): string {
  let clean = cache.get(code);
  if (!clean) {
    clean = textUtil.sanitizeSVGContent(code);

    if (clean.indexOf('<style type="text/css">') > -1) {
      clean = svgStyleCleanup(clean);
    }

    cache.set(code, clean);
  }

  return clean;
}
