import { getPanelPluginMeta } from '@grafana/runtime/internal';
import { type DashboardJson } from 'app/features/manage-dashboards/types';

/**
 * Panel types that are known to allow JavaScript code execution.
 * Community dashboards using them are refused due to security concerns.
 */
export const UNSAFE_PANEL_TYPE_SLUGS = [
  'aceiot-svg-panel',
  'ae3e-plotly-panel',
  'gapit-htmlgraphics-panel',
  'marcusolsson-dynamictext-panel',
  'volkovlabs-echarts-panel',
  'volkovlabs-form-panel',
];

type JsonObject = Record<string, unknown>;

function isJsonObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * Every panel the dashboard can render: top-level panels, children of collapsed rows, and
 * panels of pre-grid `rows` (the migrator turns those into grid panels).
 */
function collectPanels(dashboard: DashboardJson): JsonObject[] {
  const found: JsonObject[] = [];

  const visit = (panels: unknown) => {
    if (!Array.isArray(panels)) {
      return;
    }
    for (const panel of panels) {
      if (!isJsonObject(panel)) {
        continue;
      }
      found.push(panel);
      visit(panel.panels);
    }
  };

  const root: unknown = dashboard;
  if (isJsonObject(root)) {
    visit(root.panels);
    if (Array.isArray(root.rows)) {
      for (const row of root.rows) {
        if (isJsonObject(row)) {
          visit(row.panels);
        }
      }
    }
  }

  return found;
}

async function isUnsafePanelType(type: unknown): Promise<boolean> {
  if (typeof type !== 'string') {
    return false;
  }
  if (UNSAFE_PANEL_TYPE_SLUGS.includes(type.trim().toLowerCase())) {
    return true;
  }
  // Panel types also resolve through plugin alias IDs, so check the plugin that would actually load.
  const meta = await getPanelPluginMeta(type);
  return meta !== null && UNSAFE_PANEL_TYPE_SLUGS.includes(meta.id);
}

/**
 * Check if a value contains JavaScript code using heuristic pattern matching on its JSON.
 *
 * IMPORTANT: This is a heuristic-based detection, not a perfect mechanism.
 *
 * Patterns checked:
 * - HTML/Script tags: Direct XSS attack vectors
 * - Event handlers: Common JS injection points (onclick, onload, etc.)
 * - Function declarations: Actual executable code patterns
 * - eval/Function constructor: Dynamic code execution
 * - setTimeout/setInterval: Deferred code execution
 *
 * @returns true if the value might contain JavaScript code, false otherwise
 */
function canJsonContainJS(value: unknown): boolean {
  let json: string;
  try {
    json = JSON.stringify(value);
  } catch (e) {
    console.warn('Failed to stringify value', e);
    return true;
  }

  // Patterns that indicate actual JavaScript code in values
  const valuePatterns = [
    /<script\b/i, // HTML script tags
    /\bon\w+\s*=\s*/i, // HTML event handlers: onclick=, onload=, etc.
    /\bjavascript\s*:/i,
    /\bfunction\s*\(/, // Anonymous function declarations: function(
    /\bfunction\s+[\w$]+\s*\(/, // Named function declarations: function name(
    /=>\s*\{[^}]*\breturn\b/, // Arrow function with return statement: () => { return ... }
    /\beval\s*\(/i, // eval() calls
    /\bnew\s+Function\s*\(/i, // new Function() constructor
    /\bsetTimeout\s*\(/i, // setTimeout calls
    /\bsetInterval\s*\(/i, // setInterval calls
  ];

  // Patterns for suspicious JSON keys that might indicate JS hooks
  const keyPatterns = [
    /"on[a-zA-Z]+"\s*:/, // Event handlers as keys (both camelCase and lowercase): "onClick": or "onclick":
    /"beforeRender"\s*:/i, // beforeRender hook as JSON key
    /"afterRender"\s*:/i, // afterRender hook as JSON key
    /"javascript"\s*:/i, // "javascript" as a key
    /"customCode"\s*:/i, // Common pattern for custom code injection
    /"script"\s*:/i, // "script" as a JSON key
    /"handler"\s*:/i, // "handler" as a JSON key - common for event handlers
  ];

  const hasSuspiciousValue = valuePatterns.some((pattern) => {
    if (pattern.test(json)) {
      console.warn('Value contains JavaScript code');
      return true;
    }
    return false;
  });

  const hasSuspiciousKey = keyPatterns.some((pattern) => {
    if (pattern.test(json)) {
      console.warn('Value contains JavaScript code in key');
      return true;
    }
    return false;
  });

  return hasSuspiciousValue || hasSuspiciousKey;
}

/**
 * Panel title and description are excluded (already sanitized by Grafana's rendering layer).
 * Nested row children are excluded because they are checked as panels of their own.
 */
function canPanelContainJS(panel: JsonObject): boolean {
  const { title, description, panels, ...panelWithoutSanitizedFields } = panel;
  return canJsonContainJS(panelWithoutSanitizedFields);
}

/**
 * Check if input mappings might contain JavaScript code. Constant inputs become template
 * variable values that panels interpolate at render time, so they need screening whenever
 * they do not come from the user's own input.
 */
export function canInputMappingsContainJS(mappings: unknown): boolean {
  return canJsonContainJS(mappings);
}

/**
 * Check if a Grafana.com dashboard might run JavaScript: any panel uses a plugin from
 * UNSAFE_PANEL_TYPE_SLUGS, or has configuration that looks like script.
 * Must be given the exact JSON that will be rendered, after input interpolation.
 */
export async function canCommunityDashboardContainJS(dashboard: DashboardJson): Promise<boolean> {
  for (const panel of collectPanels(dashboard)) {
    if (await isUnsafePanelType(panel.type)) {
      console.warn(`Panel type ${String(panel.type)} can embed JavaScript`);
      return true;
    }
    if (canPanelContainJS(panel)) {
      return true;
    }
  }
  return false;
}
