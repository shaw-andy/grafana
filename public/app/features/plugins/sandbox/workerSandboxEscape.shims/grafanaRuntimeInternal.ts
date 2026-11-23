declare global {
  interface Window {
    __SANDBOX_CASE__?: { pluginId: string; modulePath: string };
  }
}

export async function getDatasourcePluginMeta(): Promise<null> {
  return null;
}

export async function getPanelPluginMetas(): Promise<never[]> {
  return [];
}

export async function getAppPluginMetas(): Promise<Array<{ id: string; path: string; moduleHash: string }>> {
  const spec = window.__SANDBOX_CASE__;
  if (!spec) {
    return [];
  }
  return [{ id: spec.pluginId, path: spec.modulePath, moduleHash: '' }];
}

export function invalidatePluginSettingsCache(): void {}
