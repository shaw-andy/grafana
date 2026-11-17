import { type TemplateSrv } from '@grafana/runtime';

import { type AzureMonitorResource } from '../dataquery.gen';
import { type GetMetricNamespacesQuery, type GetMetricNamesQuery } from '../types/types';

// Resource paths are resolved by the browser against the Grafana origin, so a value
// carrying dot segments, query/fragment delimiters, backslashes or percent-encoding
// could move the request off the datasource resource route.
const UNSAFE_PATH_SEGMENT_CHARACTERS = /[\\?#%\u0000-\u001f\u007f]/;

function encodeResourcePathSegment(segment: string): string {
  if (segment === '.' || segment === '..' || UNSAFE_PATH_SEGMENT_CHARACTERS.test(segment)) {
    throw new Error('Invalid Azure resource identifier');
  }
  return encodeURIComponent(segment);
}

/**
 * Validates and encodes a value that must occupy exactly one path segment, such as a subscription ID.
 */
export function encodeResourceId(value: string): string {
  if (value.includes('/')) {
    throw new Error('Invalid Azure resource identifier');
  }
  return encodeResourcePathSegment(value);
}

/**
 * Validates and encodes each segment of a slash-separated Azure resource URI.
 */
export function encodeResourceUri(uri: string): string {
  return uri.split('/').map(encodeResourcePathSegment).join('/');
}

export default class UrlBuilder {
  static buildResourceUri(templateSrv: TemplateSrv, resource: AzureMonitorResource, multipleResources?: boolean) {
    const urlArray = [];
    const { subscription, resourceGroup, metricNamespace, resourceName } = resource;
    if (subscription) {
      urlArray.push('/subscriptions', subscription);
      if (resourceGroup && !multipleResources) {
        urlArray.push('resourceGroups', resourceGroup);

        if (metricNamespace && resourceName) {
          const metricNamespaceProcessed = templateSrv.replace(metricNamespace);
          const metricNamespaceArray = metricNamespace.split('/');
          const resourceNameProcessed = templateSrv.replace(resourceName);
          const resourceNameArray = resourceName.split('/');
          const provider = metricNamespaceArray.shift();
          if (provider) {
            urlArray.push('providers', provider);
          }

          if (
            metricNamespaceProcessed.toLowerCase().startsWith('microsoft.storage/storageaccounts/') &&
            !resourceNameProcessed.endsWith('default')
          ) {
            resourceNameArray.push('default');
          }

          if (resourceNameArray.length > metricNamespaceArray.length) {
            const parentResource = resourceNameArray.shift();
            if (parentResource) {
              urlArray.push(parentResource);
            }
          }

          for (const i in metricNamespaceArray) {
            urlArray.push(metricNamespaceArray[i]);
            urlArray.push(resourceNameArray[i]);
          }
        }
      }
    }

    return urlArray.join('/');
  }

  static buildAzureMonitorGetMetricNamespacesUrl(
    baseUrl: string,
    apiVersion: string,
    query: GetMetricNamespacesQuery,
    globalRegion: boolean,
    templateSrv: TemplateSrv,
    region?: string
  ) {
    const resourceUri = UrlBuilder.buildRequestResourceUri(templateSrv, query);

    return `${baseUrl}${resourceUri}/providers/microsoft.insights/metricNamespaces?api-version=${apiVersion}${
      region ? `&region=${encodeURIComponent(region)}` : globalRegion ? '&region=global' : ''
    }`;
  }

  static buildAzureMonitorGetMetricNamesUrl(
    baseUrl: string,
    apiVersion: string,
    query: GetMetricNamesQuery,
    templateSrv: TemplateSrv,
    multipleResources?: boolean,
    region?: string,
    batchAPIEnabled?: boolean
  ) {
    // The subscription-level metricdefinitions API is not used when the batch API is enabled,
    // as the batch API handles multi-resource queries via regional endpoints.
    if (batchAPIEnabled) {
      multipleResources = false;
    }
    const { customNamespace, metricNamespace } = query;
    const resourceUri = UrlBuilder.buildRequestResourceUri(templateSrv, query, multipleResources);
    let url = `${baseUrl}${resourceUri}/providers/microsoft.insights/metricdefinitions?api-version=${apiVersion}`;
    if (customNamespace) {
      url += `&metricnamespace=${encodeURIComponent(customNamespace)}`;
    }

    if (multipleResources && !customNamespace && metricNamespace) {
      url += `&metricnamespace=${encodeURIComponent(metricNamespace)}`;
    }

    if (region && multipleResources) {
      url += `&region=${encodeURIComponent(region)}`;
    }

    return url;
  }

  static buildAzureMonitorGetLogsTableUrl(
    baseUrl: string,
    resourceUri: string,
    tableName: string,
    apiVersion = '2025-02-01'
  ) {
    return `${baseUrl}${encodeResourceUri(resourceUri)}/tables/${encodeResourceId(tableName)}?api-version=${apiVersion}`;
  }

  // Expects a query whose template variables have already been interpolated.
  private static buildRequestResourceUri(
    templateSrv: TemplateSrv,
    query: GetMetricNamespacesQuery | GetMetricNamesQuery,
    multipleResources?: boolean
  ): string {
    if ('resourceUri' in query) {
      return encodeResourceUri(query.resourceUri);
    }
    const { subscription, resourceGroup, metricNamespace, resourceName } = query;
    if (subscription) {
      encodeResourceId(subscription);
    }
    if (resourceGroup && !multipleResources) {
      encodeResourceId(resourceGroup);
    }
    return encodeResourceUri(
      UrlBuilder.buildResourceUri(
        templateSrv,
        { subscription, resourceGroup, metricNamespace, resourceName },
        multipleResources
      )
    );
  }
}
