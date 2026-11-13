import { t } from '@grafana/i18n';
import { locationService } from '@grafana/runtime';
import { createErrorNotification } from 'app/core/copy/appNotification';
import { notifyApp } from 'app/core/reducers/appNotification';
import { interpolateV1Dashboard } from 'app/features/manage-dashboards/import/utils/inputs';
import { type DataSourceInput, type DashboardJson } from 'app/features/manage-dashboards/types';
import { dispatch } from 'app/types/store';

import { DASHBOARD_LIBRARY_ROUTES } from '../../types';
import type { MappingContext } from '../SuggestedDashboardsModal';
import { fetchCommunityDashboard, type GnetDashboardDependency } from '../api/dashboardLibraryApi';
import {
  CONTENT_KINDS,
  type ContentKind,
  CREATION_ORIGINS,
  type EventLocation,
  type SourceEntryPoint,
} from '../constants';
import { type GnetDashboard, type Link } from '../types';

import { type InputMapping, tryAutoMapDatasources, parseConstantInputs, isDataSourceInput } from './autoMapDatasources';
import { canCommunityDashboardContainJS } from './communityDashboardSafety';
import type { AssistantSource } from './templateDashboardHelpers';

export const DEFAULT_SORT_ORDER = 'downloads';
export const DEFAULT_SORT_DIRECTION = 'desc';
export const INCLUDE_LOGO = true;
export const INCLUDE_SCREENSHOTS = true;

/**
 * Extract thumbnail URL from dashboard screenshots
 */
export function getThumbnailUrl(dashboard: GnetDashboard): string {
  const thumbnail = dashboard.screenshots?.[0]?.links.find((l: Link) => l.rel === 'image')?.href ?? '';
  return thumbnail ? `/api/gnet${thumbnail}` : '';
}

/**
 * Extract logo URL from dashboard logos
 */
export function getLogoUrl(dashboard: GnetDashboard): string {
  const logo = dashboard.logos?.large || dashboard.logos?.small;
  if (logo?.content && logo?.type) {
    return `data:${logo.type};base64,${logo.content}`;
  }
  return '';
}

/**
 * Format date string for display
 */
function formatDate(dateString?: string): string {
  if (!dateString) {
    return 'N/A';
  }
  const date = new Date(dateString);
  return date.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

/**
 * Build Grafana.com URL for a dashboard
 */
export function buildGrafanaComUrl(dashboard: GnetDashboard): string {
  return `https://grafana.com/grafana/dashboards/${dashboard.id}-${dashboard.slug}/`;
}

/**
 * Build dashboard details object for display in card
 */
export interface DashboardDetails {
  id: string;
  datasource: string;
  dependencies: string[];
  publishedBy: string;
  lastUpdate: string;
  grafanaComUrl: string;
}

export function buildDashboardDetails(dashboard: GnetDashboard): DashboardDetails {
  return {
    id: String(dashboard.id),
    datasource: dashboard.datasource || 'N/A',
    dependencies: dashboard.datasource ? [dashboard.datasource] : [],
    publishedBy: dashboard.orgName || dashboard.userName || 'Grafana Community',
    lastUpdate: formatDate(dashboard.updatedAt || dashboard.publishedAt),
    grafanaComUrl: buildGrafanaComUrl(dashboard),
  };
}

/**
 * Navigate to dashboard template route with mappings
 */
export function navigateToTemplate(
  dashboardTitle: string,
  gnetId: number,
  datasourceUid: string,
  mappings: InputMapping[],
  sourceEntryPoint: SourceEntryPoint,
  eventLocation: EventLocation,
  contentKind: ContentKind,
  datasourceTypes?: string[],
  assistantSource?: AssistantSource
): void {
  const searchParams = new URLSearchParams({
    datasource: datasourceUid,
    title: dashboardTitle,
    gnetId: String(gnetId),
    sourceEntryPoint,
    creationOrigin: CREATION_ORIGINS.DASHBOARD_LIBRARY_COMMUNITY_DASHBOARD,
    contentKind,
    eventLocation,
    mappings: JSON.stringify(mappings),
    suggestedDashboardBanner: 'true',
  });

  // Add datasource types for tracking if available
  if (datasourceTypes && datasourceTypes.length > 0) {
    searchParams.set('datasourceTypes', JSON.stringify(datasourceTypes));
  }

  if (assistantSource) {
    searchParams.set('assistantSource', assistantSource);
  }

  locationService.push({
    pathname: DASHBOARD_LIBRARY_ROUTES.Template,
    search: searchParams.toString(),
  });
}

interface UseCommunityDashboardParams {
  dashboard: GnetDashboard;
  datasourceUid: string;
  sourceEntryPoint: SourceEntryPoint;
  eventLocation: EventLocation;
  onShowMapping?: (context: MappingContext) => void;
  assistantSource?: AssistantSource;
}

/**
 * Handles the flow when a user selects a community dashboard:
 * 1. Tracks analytics
 * 2. Fetches full dashboard JSON with __inputs
 * 3. Filters out dashboards that contain JavaScript code due to security reasons
 * 4. Attempts auto-mapping of datasources
 * 5. Either navigates directly or shows mapping form
 */
export async function onUseCommunityDashboard({
  dashboard,
  datasourceUid,
  sourceEntryPoint,
  eventLocation,
  onShowMapping,
  assistantSource,
}: UseCommunityDashboardParams): Promise<void> {
  // Note: item_clicked tracking is done by the caller (CommunityDashboardSection or SuggestedDashboards)
  // with the correct discoveryMethod before calling this function
  try {
    // Fetch full dashboard from Gcom, this is the JSON with __inputs
    const fullDashboard = await fetchCommunityDashboard(dashboard.id);
    const dashboardJson = fullDashboard.json;

    if (await canCommunityDashboardContainJS(dashboardJson)) {
      throw new Error(`Community dashboard ${dashboard.id} "${dashboard.name}" might contain JavaScript code`);
    }

    // Parse datasource requirements from __inputs
    const dsInputs: DataSourceInput[] = dashboardJson.__inputs?.filter(isDataSourceInput) || [];

    // Extract datasource types for tracking purposes from dependencies
    const datasourceTypes =
      fullDashboard.dependencies?.items
        ?.filter((dep: GnetDashboardDependency) => dep.pluginTypeCode === 'datasource')
        .map((dep: GnetDashboardDependency) => dep.pluginSlug)
        .filter(Boolean) || [];

    // Parse constant inputs - these always need user review
    const constantInputs = parseConstantInputs(dashboardJson.__inputs || []);

    // Try auto-mapping datasources
    const mappingResult = await tryAutoMapDatasources(dsInputs, datasourceUid);

    // Decide whether to show mapping form or navigate directly
    // Show mapping form if: (a) there are unmapped datasources OR (b) there are constants
    const needsMapping = mappingResult.unmappedDsInputs.length > 0 || constantInputs.length > 0;

    if (!needsMapping) {
      // No mapping needed - all datasources auto-mapped, no constants
      navigateToTemplate(
        dashboard.name,
        dashboard.id,
        datasourceUid,
        mappingResult.mappings,
        sourceEntryPoint,
        eventLocation,
        CONTENT_KINDS.COMMUNITY_DASHBOARD,
        datasourceTypes,
        assistantSource
      );
    } else {
      // Show mapping form for unmapped datasources and/or constants
      if (onShowMapping) {
        onShowMapping({
          dashboardName: dashboard.name,
          dashboardJson,
          unmappedDsInputs: mappingResult.unmappedDsInputs,
          constantInputs,
          existingMappings: mappingResult.mappings,
          contentKind: CONTENT_KINDS.COMMUNITY_DASHBOARD,
          onInterpolateAndNavigate: (mappings) =>
            navigateToTemplate(
              dashboard.name,
              dashboard.id,
              datasourceUid,
              mappings,
              sourceEntryPoint,
              eventLocation,
              CONTENT_KINDS.COMMUNITY_DASHBOARD,
              datasourceTypes,
              assistantSource
            ),
        });
      }
    }
  } catch (err) {
    console.error('Error loading community dashboard:', err);
    dispatch(
      notifyApp(
        createErrorNotification(t('dashboard-library.community-error-title', 'Error loading community dashboard'))
      )
    );
    throw err;
  }
}

/**
 * Interpolate a community dashboard for compatibility checking.
 *
 * This function fetches the dashboard from Grafana.com, auto-maps datasource inputs,
 * and returns the interpolated dashboard with template variables resolved.
 *
 * @throws Error if auto-mapping fails - compatibility check requires all datasource inputs to be resolved
 * @param dashboardId - The Grafana.com dashboard ID
 * @param datasourceUid - The UID of the datasource to map to
 * @returns Promise<DashboardJson> - The interpolated dashboard with resolved template variables
 */
export async function interpolateDashboardForCompatibilityCheck(
  dashboardId: number,
  datasourceUid: string
): Promise<DashboardJson> {
  // 1. Fetch full dashboard JSON from Grafana.com
  const gnetResponse = await fetchCommunityDashboard(dashboardId);
  const dashboardJson = gnetResponse.json;

  // 2. Extract datasource inputs from dashboard's __inputs array
  const dsInputs: DataSourceInput[] = dashboardJson.__inputs?.filter(isDataSourceInput) || [];

  // 3. Auto-map datasources using existing utility
  const mappingResult = await tryAutoMapDatasources(dsInputs, datasourceUid);

  // 4. Check if auto-mapping was successful
  // Compatibility check requires all datasource variables to be resolved
  if (!mappingResult.allMapped) {
    throw new Error(
      t(
        'dashboard-library.compatibility-auto-map-failed',
        'Unable to automatically map all datasource inputs for this dashboard. Compatibility check requires all datasource variables to be resolved.'
      )
    );
  }

  // 5. Interpolate in the frontend — no backend round-trip needed
  const inputs: InputMapping[] = mappingResult.mappings;

  return interpolateV1Dashboard(dashboardJson, inputs);
}
