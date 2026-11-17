import { type DataFrame } from '@grafana/data';
import { config as runtimeConfig } from '@grafana/runtime';
import { type ResourceDimensionConfig, ResourceDimensionMode } from '@grafana/schema';

import { type DimensionSupplier } from './types';
import { findField, getLastNotNullFieldValue } from './utils';

//---------------------------------------------------------
// Resource dimension
//---------------------------------------------------------
export function getPublicOrAbsoluteUrl(path: unknown): string {
  if (!path || typeof path !== 'string') {
    return '';
  }

  // NOTE: The value of `path` could be either an URL string or a relative
  //       path to a Grafana CDN asset served from the CDN.
  const isUrl = path.indexOf(':/') > 0;
  // Falls back to the default build directory when no entry point has set the global.
  const buildPath = window.__grafana_build_path__ || 'public/build/';

  if (!isUrl && !isSafeRelativeAssetPath(path)) {
    return '';
  }

  const url = isUrl ? path : `${buildPath}${path}`;
  return isAllowedResourceUrl(url, buildPath) ? url : '';
}

function isSafeRelativeAssetPath(path: string): boolean {
  let decoded = path;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    return false;
  }

  for (const value of [path, decoded]) {
    if (value.startsWith('/') || value.includes('\\') || /(^|\/)\.\.(\/|$)/.test(value)) {
      return false;
    }
  }
  return true;
}

// Resource URLs are loaded by the viewer's browser with their Grafana cookies whenever they point at the
// Grafana host, so on that host only static asset locations may be requested. Hostname (not origin) is
// compared because cookies ignore the port and browsers upgrade http image requests on https pages.
function isAllowedResourceUrl(url: string, buildPath: string): boolean {
  let resolved: URL;
  let buildRoot: URL;
  let staticRoot: URL;
  try {
    resolved = new URL(url, document.baseURI);
    buildRoot = new URL(buildPath, document.baseURI);
    staticRoot = new URL(`${runtimeConfig.appSubUrl ?? ''}/public/`, window.location.origin);
  } catch {
    return false;
  }

  if (resolved.protocol !== 'http:' && resolved.protocol !== 'https:') {
    return false;
  }

  if (resolved.href.startsWith(buildRoot.href)) {
    return true;
  }

  if (resolved.hostname !== window.location.hostname) {
    return true;
  }

  return resolved.pathname.startsWith(staticRoot.pathname);
}

export function getResourceDimension(
  frame: DataFrame | undefined,
  config: ResourceDimensionConfig
): DimensionSupplier<string> {
  const mode = config.mode ?? ResourceDimensionMode.Fixed;
  if (mode === ResourceDimensionMode.Fixed) {
    const v = getPublicOrAbsoluteUrl(config.fixed);
    return {
      isAssumed: !Boolean(v),
      fixed: v,
      value: () => v,
      get: (i) => v,
    };
  }

  const field = findField(frame, config.field);
  if (!field) {
    const v = '';
    return {
      isAssumed: true,
      fixed: v,
      value: () => v,
      get: (i) => v,
    };
  }

  if (mode === ResourceDimensionMode.Mapping) {
    const mapper = (v: string) => getPublicOrAbsoluteUrl(`${v}`);
    return {
      field,
      get: (i) => mapper(field.values[i]),
      value: () => mapper(getLastNotNullFieldValue(field)),
    };
  }

  // mode === ResourceDimensionMode.Field case
  const getImageOrIcon = (value: unknown): string => {
    if (typeof value !== 'string' && typeof value !== 'number') {
      return '';
    }

    let url = typeof value === 'string' ? value : '';
    if (field && field.display) {
      const displayValue = field.display(value);
      if (displayValue.icon) {
        url = displayValue.icon;
      }
    }

    const noIconFound = !url;
    if (noIconFound) {
      return '';
    }

    return getPublicOrAbsoluteUrl(url);
  };

  return {
    field,
    get: (index: number): string => getImageOrIcon(field.values[index]),
    value: () => getImageOrIcon(getLastNotNullFieldValue(field)),
  };
}
