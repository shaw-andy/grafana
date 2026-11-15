import { OrgRole, PluginIncludeType, type PluginInclude } from '@grafana/data';
import { contextSrv } from 'app/core/services/context_srv';

interface PageInclude {
  path: string;
  include: PluginInclude;
}

/**
 * Checks whether the current user may open a URL of an app plugin, using the same rules as the
 * backend app route guard: the most specific page include covering the URL gates it, and a URL that
 * no page include covers is denied. URLs under /a/<pluginId> are only gated by includes under that
 * path, and are not restricted here when the app declares none.
 */
export function canAccessAppPluginPath(
  pluginId: string,
  includes: PluginInclude[] | undefined,
  pathname: string
): boolean {
  const allPages = pageIncludes(includes);
  const appRoot = normalizePath(`/a/${pluginId}`);
  const appPages = allPages.filter((page) => isUnderIncludePath(page.path, appRoot));

  // The plugin's own router decides what renders under any URL, so every reading of the path must be allowed.
  return pathVariants(stripQueryAndHash(pathname)).every((path) => {
    const pages = isUnderIncludePath(path, appRoot) ? appPages : allPages;
    if (pages.length === 0) {
      return true;
    }
    const matched = longestMatchingIncludes(pages, path);
    return matched.length > 0 && matched.every(({ include }) => canOpenInclude(include));
  });
}

function canOpenInclude(include: PluginInclude): boolean {
  if (include.action) {
    return contextSrv.hasPermission(include.action);
  }

  if (contextSrv.isGrafanaAdmin || contextSrv.user.orgRole === OrgRole.Admin) {
    return true;
  }

  const includeRole = include.role ?? '';
  if (!includeRole || (contextSrv.isEditor && includeRole === OrgRole.Viewer)) {
    return true;
  }

  return contextSrv.hasRole(includeRole);
}

function pageIncludes(includes: PluginInclude[] | undefined): PageInclude[] {
  const pages: PageInclude[] = [];
  for (const include of includes ?? []) {
    if (include.type !== PluginIncludeType.page || !include.path) {
      continue;
    }
    pages.push({ path: normalizePath(cleanPath(stripQueryAndHash(include.path))), include });
  }
  return pages;
}

function longestMatchingIncludes(pages: PageInclude[], path: string): PageInclude[] {
  let matched: PageInclude[] = [];
  for (const page of pages) {
    if (!isUnderIncludePath(path, page.path)) {
      continue;
    }
    if (matched.length > 0 && page.path.length < matched[0].path.length) {
      continue;
    }
    if (matched.length > 0 && page.path.length > matched[0].path.length) {
      matched = [];
    }
    matched.push(page);
  }
  return matched;
}

function pathVariants(pathname: string): string[] {
  const variants = new Set<string>();
  for (const path of [pathname, safeDecode(pathname)]) {
    variants.add(normalizePath(path));
    variants.add(normalizePath(cleanPath(path)));
  }
  return [...variants];
}

function isUnderIncludePath(path: string, includePath: string): boolean {
  return includePath === '' || path === includePath || path.startsWith(includePath + '/');
}

function stripQueryAndHash(path: string): string {
  return path.split(/[?#]/)[0];
}

function safeDecode(path: string): string {
  try {
    return decodeURIComponent(path);
  } catch {
    return path;
  }
}

function cleanPath(path: string): string {
  const segments: string[] = [];
  for (const segment of path.split('/')) {
    if (segment === '' || segment === '.') {
      continue;
    }
    if (segment === '..') {
      segments.pop();
      continue;
    }
    segments.push(segment);
  }
  return segments.join('/');
}

// Case-insensitive because react-router matches routes case-insensitively by default.
function normalizePath(path: string): string {
  return path.replace(/^\/+|\/+$/g, '').toLowerCase();
}
