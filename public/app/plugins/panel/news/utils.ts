import { FieldType, type DataFrame, dateTime } from '@grafana/data';
import { config } from '@grafana/runtime';

import { type Feed } from './types';

function normalizeHostname(hostname: string): string {
  return hostname.toLowerCase().replace(/\.+$/, '');
}

function parseUrl(value: string, base?: string): URL | undefined {
  try {
    return new URL(value, base);
  } catch {
    return undefined;
  }
}

function getGrafanaHostnames(): Set<string> {
  const hostnames = new Set<string>([normalizeHostname(window.location.hostname)]);
  const appUrl = config.appUrl ? parseUrl(config.appUrl, window.location.href) : undefined;
  if (appUrl) {
    hostnames.add(normalizeHostname(appUrl.hostname));
  }
  return hostnames;
}

/**
 * Feed images are loaded by every viewer's browser, so only absolute http(s) URLs on a host
 * other than this Grafana server are allowed. Relative, protocol-relative and same-host URLs
 * would be requested with the viewer's session cookie.
 */
export function getExternalImageUrl(value: unknown): string | undefined {
  if (typeof value !== 'string' || !/^https?:\/\//i.test(value)) {
    return undefined;
  }

  const url = parseUrl(value);
  if (!url || (url.protocol !== 'http:' && url.protocol !== 'https:')) {
    return undefined;
  }

  if (getGrafanaHostnames().has(normalizeHostname(url.hostname))) {
    return undefined;
  }

  return url.href;
}

export function feedToDataFrame(feed: Feed): DataFrame {
  const date: number[] = [];
  const title: string[] = [];
  const link: string[] = [];
  const content: string[] = [];
  const ogImage: Array<string | undefined | null> = [];

  for (const item of feed.items) {
    const val = dateTime(item.pubDate);

    try {
      date.push(val.valueOf());
      title.push(item.title);
      link.push(item.link);
      ogImage.push(item.ogImage);

      if (item.content) {
        const body = item.content.replace(/<\/?[^>]+(>|$)/g, '');
        content.push(body);
      }
    } catch (err) {
      console.warn('Error reading news item:', err, item);
    }
  }

  return {
    fields: [
      { name: 'date', type: FieldType.time, config: { displayName: 'Date' }, values: date },
      { name: 'title', type: FieldType.string, config: {}, values: title },
      { name: 'link', type: FieldType.string, config: {}, values: link },
      { name: 'content', type: FieldType.string, config: {}, values: content },
      { name: 'ogImage', type: FieldType.string, config: {}, values: ogImage },
    ],
    length: date.length,
  };
}
