const noop = () => {};

export function getLogger() {
  return {
    logWarning: noop,
    logError: noop,
    logInfo: noop,
  };
}

// Installed community plugin settings, the success path of the sandbox eligibility check.
export async function getPluginSettings(pluginId: string) {
  return {
    id: pluginId,
    name: pluginId,
    signatureType: 'community',
    signature: 'valid',
  };
}
