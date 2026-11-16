import { BASE_PATH, UIMap } from '../constants';
import { type AuthProviderInfo } from '../types';

export function getProviderUrl(provider: AuthProviderInfo) {
  return BASE_PATH + (provider.configPath || provider.id);
}

export function isKnownProvider(provider: string): boolean {
  return Object.hasOwn(UIMap, provider);
}

// The provider usually comes from the page URL, and requests resolve relative to the document base,
// so an unchecked value could retarget the request to another same-origin endpoint.
export function getSSOSettingsUrl(provider: string): string {
  if (!isKnownProvider(provider)) {
    throw new Error(`Unknown authentication provider: ${provider}`);
  }
  return `/api/v1/sso-settings/${encodeURIComponent(provider)}`;
}

export const isUrlValid = (url: unknown): boolean => {
  if (typeof url !== 'string') {
    return false;
  }
  try {
    const parsedUrl = new URL(url);
    return parsedUrl.protocol.includes('http');
  } catch (_) {
    return false;
  }
};

export const isValidDomain = (domain: string): boolean => {
  if (typeof domain !== 'string' || !domain.length) {
    return false;
  }

  const domainRegex =
    /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,6}$/;
  return domainRegex.test(domain);
};
