import createVirtualEnvironment from '@locker/near-membrane-dom';
import { type ProxyTarget } from '@locker/near-membrane-shared';

import { PluginType } from '@grafana/data';
import { defaultTrustedTypesPolicy } from 'app/core/trustedTypePolicies';

import { distortLiveApis, getGeneralSandboxDistortionMap } from './distortions';
import {
  getSafeSandboxDomElement,
  isDomElement,
  isLiveTarget,
  markDomElementStyleAsALiveTarget,
  patchObjectAsLiveTarget,
} from './documentSandbox';
import { type SandboxEnvironment, type SandboxPluginMeta } from './types';

const meta: SandboxPluginMeta = {
  id: 'sandbox-script-insertion-test',
  type: PluginType.panel,
  module: '/sandbox-script-insertion-test/module.js',
};

/**
 * Runs one plugin script in the near-membrane environment built by
 * sandboxPluginLoader.ts. The distortion callback follows
 * doImportPluginModuleInSandbox in that file.
 */
function runInPluginSandbox(pluginCode: string) {
  const generalDistortionMap = getGeneralSandboxDistortionMap();
  let sandboxEnvironment: SandboxEnvironment;

  function distortionCallback(originalValue: ProxyTarget): ProxyTarget {
    if (isDomElement(originalValue)) {
      const element = getSafeSandboxDomElement(originalValue, meta.id);
      markDomElementStyleAsALiveTarget(element);
      return element;
    } else {
      patchObjectAsLiveTarget(originalValue);
    }

    const staticDistortion = generalDistortionMap.get(originalValue);
    if (staticDistortion) {
      const distorted = staticDistortion(originalValue, meta, sandboxEnvironment);
      if (typeof distorted === 'function' || (typeof distorted === 'object' && distorted !== null)) {
        return distorted;
      }
    }

    const liveDistortion = distortLiveApis(originalValue);
    if (liveDistortion) {
      return liveDistortion;
    }
    return originalValue;
  }

  sandboxEnvironment = createVirtualEnvironment(window, {
    distortionCallback,
    defaultPolicy: defaultTrustedTypesPolicy,
    liveTargetCallback: isLiveTarget,
    endowments: Object.getOwnPropertyDescriptors({
      locationSandbox: window.location,
    }),
  });

  sandboxEnvironment.evaluate(pluginCode);
}

window.__runInPluginSandbox = runInPluginSandbox;

declare global {
  interface Window {
    __runInPluginSandbox?: (pluginCode: string) => void;
    __parentRealmScript?: string;
  }
}
