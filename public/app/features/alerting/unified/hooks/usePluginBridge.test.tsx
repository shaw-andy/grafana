import { renderHook, waitFor } from '@testing-library/react';

import { OrgRole, PluginIncludeType } from '@grafana/data';
import { invalidateCachedPromisesCache } from '@grafana/runtime/internal';
import { contextSrv } from 'app/core/services/context_srv';

import { setupMswServer } from '../mockApi';
import { addPlugin, disablePlugin, failPlugin, removePlugin } from '../mocks/server/configure';
import { pluginMeta } from '../testSetup/plugins';
import { SupportedPlugin } from '../types/pluginBridges';

import { canAccessPluginPage, useIrmPlugin } from './usePluginBridge';

const server = setupMswServer();

describe('useIrmPlugin', () => {
  let requestedPluginSettings: string[] = [];

  const recordPluginSettingsRequest = ({ request }: { request: Request }) => {
    const match = new URL(request.url).pathname.match(/^\/api\/plugins\/(.+)\/settings$/);
    if (match) {
      requestedPluginSettings.push(match[1]);
    }
  };

  beforeAll(() => {
    server.events.on('request:start', recordPluginSettingsRequest);
  });

  afterAll(() => {
    server.events.removeListener('request:start', recordPluginSettingsRequest);
  });

  beforeEach(() => {
    requestedPluginSettings = [];
  });

  afterEach(() => {
    invalidateCachedPromisesCache();
  });

  it('should return IRM plugin ID when IRM plugin is installed', async () => {
    addPlugin(pluginMeta[SupportedPlugin.Irm]);

    const { result } = renderHook(() => useIrmPlugin(SupportedPlugin.OnCall));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.pluginId).toBe(SupportedPlugin.Irm);
    expect(result.current.installed).toBe(true);
    expect(result.current.settings).toBeDefined();
  });

  it('should return OnCall plugin ID when IRM plugin is not installed', async () => {
    const { result } = renderHook(() => useIrmPlugin(SupportedPlugin.OnCall));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.pluginId).toBe(SupportedPlugin.OnCall);
    expect(result.current.installed).toBe(true);
    expect(result.current.settings).toBeDefined();
  });

  it('should return Incident plugin ID when IRM plugin is not installed', async () => {
    const { result } = renderHook(() => useIrmPlugin(SupportedPlugin.Incident));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.pluginId).toBe(SupportedPlugin.Incident);
    expect(result.current.installed).toBe(true);
    expect(result.current.settings).toBeDefined();
  });

  it('should return loading state while fetching plugins', async () => {
    const { result } = renderHook(() => useIrmPlugin(SupportedPlugin.OnCall));

    expect(result.current.loading).toBe(true);
    expect(result.current.installed).toBeUndefined();

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });
  });

  it('should never report "not installed" before the check has settled', async () => {
    const states: Array<{ loading: boolean; installed?: boolean }> = [];

    const { result } = renderHook(() => {
      const bridge = useIrmPlugin(SupportedPlugin.OnCall);
      states.push({ loading: bridge.loading, installed: bridge.installed });
      return bridge;
    });

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    // a settled state must be the final answer – no flash of installed: false in between
    const firstSettled = states.findIndex((state) => !state.loading);
    expect(states.slice(firstSettled).every((state) => state.installed === true)).toBe(true);
  });

  it('should not request settings for a plugin that is not installed', async () => {
    removePlugin(SupportedPlugin.OnCall);

    const { result } = renderHook(() => useIrmPlugin(SupportedPlugin.OnCall));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(requestedPluginSettings).not.toContain(SupportedPlugin.OnCall);
  });

  it('should not request the fallback plugin settings when IRM is installed', async () => {
    addPlugin(pluginMeta[SupportedPlugin.Irm]);

    const { result } = renderHook(() => useIrmPlugin(SupportedPlugin.OnCall));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(requestedPluginSettings).toContain(SupportedPlugin.Irm);
    expect(requestedPluginSettings).not.toContain(SupportedPlugin.OnCall);
  });

  it('should return installed false when neither plugin is installed (404)', async () => {
    removePlugin(SupportedPlugin.OnCall);

    const { result } = renderHook(() => useIrmPlugin(SupportedPlugin.OnCall));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.pluginId).toBe(SupportedPlugin.OnCall);
    expect(result.current.installed).toBe(false);
    expect(result.current.error).toBeUndefined();
  });

  it('should return installed false when plugin is disabled', async () => {
    disablePlugin(SupportedPlugin.OnCall);

    const { result } = renderHook(() => useIrmPlugin(SupportedPlugin.OnCall));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.pluginId).toBe(SupportedPlugin.OnCall);
    expect(result.current.installed).toBe(false);
    expect(result.current.error).toBeUndefined();
  });

  it('should propagate error when plugin check fails with a non-404 error', async () => {
    failPlugin(SupportedPlugin.OnCall, 500);

    const { result } = renderHook(() => useIrmPlugin(SupportedPlugin.OnCall));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.pluginId).toBe(SupportedPlugin.OnCall);
    expect(result.current.installed).toBeUndefined();
    expect(result.current.error).toBeDefined();
  });

  it('should return IRM plugin ID when both IRM and OnCall are installed', async () => {
    addPlugin(pluginMeta[SupportedPlugin.Irm]);

    const { result } = renderHook(() => useIrmPlugin(SupportedPlugin.OnCall));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.pluginId).toBe(SupportedPlugin.Irm);
    expect(result.current.installed).toBe(true);
    expect(result.current.settings).toEqual(expect.objectContaining({ id: SupportedPlugin.Irm }));
  });

  it('should return IRM plugin ID when both IRM and Incident are installed', async () => {
    addPlugin(pluginMeta[SupportedPlugin.Irm]);

    const { result } = renderHook(() => useIrmPlugin(SupportedPlugin.Incident));

    await waitFor(() => {
      expect(result.current.loading).toBe(false);
    });

    expect(result.current.pluginId).toBe(SupportedPlugin.Irm);
    expect(result.current.installed).toBe(true);
    expect(result.current.settings).toEqual(expect.objectContaining({ id: SupportedPlugin.Irm }));
  });
});

describe('canAccessPluginPage', () => {
  const previousRole = contextSrv.user.orgRole;
  const previousPermissions = contextSrv.user.permissions;
  const previousIsEditor = contextSrv.isEditor;
  const previousIsGrafanaAdmin = contextSrv.isGrafanaAdmin;

  afterEach(() => {
    contextSrv.user.orgRole = previousRole;
    contextSrv.user.permissions = previousPermissions;
    contextSrv.isEditor = previousIsEditor;
    contextSrv.isGrafanaAdmin = previousIsGrafanaAdmin;
  });

  it('returns false when include requires action and user lacks permission', () => {
    contextSrv.user.permissions = {};
    const settings = {
      ...pluginMeta[SupportedPlugin.Incident],
      includes: [
        {
          type: PluginIncludeType.page,
          name: 'Declare incident',
          path: '/a/grafana-incident-app/incidents/declare',
          action: 'grafana-incident-app.incidents:write',
        },
      ],
    };

    expect(canAccessPluginPage(settings, '/a/grafana-incident-app/incidents/declare')).toBe(false);
  });

  it('returns true when include requires action and user has permission', () => {
    contextSrv.user.permissions = { 'grafana-incident-app.incidents:write': true };
    const settings = {
      ...pluginMeta[SupportedPlugin.Incident],
      includes: [
        {
          type: PluginIncludeType.page,
          name: 'Declare incident',
          path: '/a/grafana-incident-app/incidents/declare',
          action: 'grafana-incident-app.incidents:write',
        },
      ],
    };

    expect(canAccessPluginPage(settings, '/a/grafana-incident-app/incidents/declare')).toBe(true);
  });

  it('returns false when include role is editor and user is viewer', () => {
    contextSrv.user.orgRole = OrgRole.Viewer;
    contextSrv.isEditor = false;
    const settings = {
      ...pluginMeta[SupportedPlugin.Incident],
      includes: [
        {
          type: PluginIncludeType.page,
          name: 'Declare incident',
          path: '/a/grafana-incident-app/incidents/declare',
          role: OrgRole.Editor,
        },
      ],
    };

    expect(canAccessPluginPage(settings, '/a/grafana-incident-app/incidents/declare')).toBe(false);
  });

  const openPlugin = {
    ...pluginMeta[SupportedPlugin.Incident],
    includes: [
      {
        type: PluginIncludeType.page,
        name: 'Root',
        path: '/a/open-plugin',
        role: OrgRole.Viewer,
        action: 'plugins.app:access',
      },
      {
        type: PluginIncludeType.page,
        name: 'Editor',
        path: '/a/open-plugin/editor-page',
        role: OrgRole.Editor,
      },
      {
        type: PluginIncludeType.page,
        name: 'Admin',
        path: '/a/open-plugin/admin-page',
        role: OrgRole.Admin,
      },
      {
        type: PluginIncludeType.page,
        name: 'Secret',
        path: '/a/open-plugin/secret',
        role: OrgRole.Viewer,
        action: 'open-plugin.secret:read',
      },
    ],
  };

  const extPlugin = {
    ...pluginMeta[SupportedPlugin.Incident],
    includes: [
      {
        type: PluginIncludeType.page,
        name: 'Exposed components',
        path: '/a/ext-plugin/exposed-components',
        role: OrgRole.Admin,
      },
    ],
  };

  it('gates a child of an admin include for a viewer who has application access', () => {
    contextSrv.user.orgRole = OrgRole.Viewer;
    contextSrv.isEditor = false;
    contextSrv.isGrafanaAdmin = false;
    contextSrv.user.permissions = { 'plugins.app:access': true };

    expect(canAccessPluginPage(openPlugin, '/a/open-plugin/public')).toBe(true);
    expect(canAccessPluginPage(openPlugin, '/a/open-plugin/admin-page')).toBe(false);
    expect(canAccessPluginPage(openPlugin, '/a/open-plugin/admin-page/extra')).toBe(false);
    expect(canAccessPluginPage(openPlugin, '/a/open-plugin/admin-page/extra?next=/a/open-plugin')).toBe(false);
    expect(canAccessPluginPage(openPlugin, '/a/open-plugin/admin-page-other')).toBe(true);
    expect(canAccessPluginPage(openPlugin, '/a/open-plugin/editor-page/item')).toBe(false);
    expect(canAccessPluginPage(openPlugin, '/a/open-plugin/secret/item')).toBe(false);
  });

  it('lets a viewer with the page action open a child of that include', () => {
    contextSrv.user.orgRole = OrgRole.Viewer;
    contextSrv.isEditor = false;
    contextSrv.isGrafanaAdmin = false;
    contextSrv.user.permissions = { 'plugins.app:access': true, 'open-plugin.secret:read': true };

    expect(canAccessPluginPage(openPlugin, '/a/open-plugin/secret/item')).toBe(true);
  });

  it('denies paths that are not under an include the viewer may open', () => {
    contextSrv.user.orgRole = OrgRole.Viewer;
    contextSrv.isEditor = false;
    contextSrv.isGrafanaAdmin = false;
    contextSrv.user.permissions = { 'plugins.app:access': true };

    expect(canAccessPluginPage(extPlugin, '/a/ext-plugin/exposed-components')).toBe(false);
    expect(canAccessPluginPage(extPlugin, '/a/ext-plugin/exposed-components/extra')).toBe(false);
    expect(canAccessPluginPage(extPlugin, '/a/ext-plugin')).toBe(false);
    expect(canAccessPluginPage(extPlugin, '/a/ext-plugin/other')).toBe(false);
    expect(canAccessPluginPage(extPlugin, '/a/ext-plugin/other/../exposed-components/extra')).toBe(false);
  });

  it('still allows an app that declares no page includes', () => {
    contextSrv.user.orgRole = OrgRole.Viewer;
    contextSrv.user.permissions = {};

    expect(
      canAccessPluginPage({ ...pluginMeta[SupportedPlugin.Incident], includes: [] }, '/a/bare-plugin/anywhere')
    ).toBe(true);
  });

  it('allows a grafana admin through a role include prefix but not through an undeclared path', () => {
    contextSrv.user.orgRole = OrgRole.Viewer;
    contextSrv.isEditor = false;
    contextSrv.isGrafanaAdmin = true;
    contextSrv.user.permissions = { 'plugins.app:access': true };

    expect(canAccessPluginPage(extPlugin, '/a/ext-plugin/exposed-components/extra')).toBe(true);
    expect(canAccessPluginPage(extPlugin, '/a/ext-plugin/other')).toBe(false);
  });
});
