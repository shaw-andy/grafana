// Same fields the real boot config reads on the plugin-sandbox load path.
// index.html copies frontend settings onto this object before the app starts.
export const config = {
  appSubUrl: '',
  pluginsCDNBaseURL: '',
  buildInfo: { env: 'production' },
  featureToggles: { pluginsSriChecks: false },
  cspReportOnlyEnabled: false,
  trustedTypesDefaultPolicyEnabled: false,
  enableFrontendSandboxForPlugins: [] as string[],
  bootData: { settings: {}, user: {} },
};
