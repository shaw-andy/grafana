/**
 * Narrow stand-in for @grafana/runtime config. The insertion distortions do not
 * read it. buildInfo.env is production so the sandbox endowments stay quiet.
 */
export const config = {
  buildInfo: { env: 'production' },
  cspReportOnlyEnabled: false,
  trustedTypesDefaultPolicyEnabled: false,
  featureToggles: {},
  enableFrontendSandboxForPlugins: [] as string[],
};
