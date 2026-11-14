import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { type JSX } from 'react';

import { AppPlugin, PluginExtensionPoints } from '@grafana/data';
import { config, locationService, setReturnToPreviousHook } from '@grafana/runtime';

import { ExtensionRegistriesProvider } from '../../../plugins/extensions/ExtensionRegistriesContext';
import { AddedComponentsRegistry } from '../../../plugins/extensions/registry/AddedComponentsRegistry';
import { AddedFunctionsRegistry } from '../../../plugins/extensions/registry/AddedFunctionsRegistry';
import { AddedLinksRegistry } from '../../../plugins/extensions/registry/AddedLinksRegistry';
import { ExposedComponentsRegistry } from '../../../plugins/extensions/registry/ExposedComponentsRegistry';
import { type PluginExtensionRegistries } from '../../../plugins/extensions/registry/types';
import { usePluginLinks } from '../../../plugins/extensions/usePluginLinks';
import KeyValuesTable from '../components/TraceTimelineViewer/SpanDetail/KeyValuesTable';

import { getTraceViewLinkAttrs, openTraceViewHref } from './openTraceViewHref';

jest.mock('../../../plugins/extensions/useLoadAppPlugins', () => ({
  useLoadAppPlugins: () => ({ isLoading: false }),
}));

const ATTACKER_HOST = 'attacker.example';
const ATTRIBUTE_KEY = 'service.name';
const ATTRIBUTE_VALUE = 'payments';
const LINK_TITLE = 'Service catalog';
const LINK_DESCRIPTION = 'Open the service';

// Same-origin absolute URLs whose path the URL parser rewrites to a protocol-relative address.
const doubleSlashPaths = [
  `//${ATTACKER_HOST}/phish`,
  `/\\${ATTACKER_HOST}/phish`,
  `\\\\${ATTACKER_HOST}/phish`,
  `/\\/${ATTACKER_HOST}/phish`,
  `//${ATTACKER_HOST}/phish?q=1#section`,
];

function pageHost(): string {
  return window.location.host;
}

function hostOf(href: string): string {
  return new URL(href, window.location.href).host;
}

function sameOriginPath(suffix: string): string {
  return `${window.location.origin}${suffix}`;
}

function registerInstalledAppLink(path: string, openInNewTab?: boolean): PluginExtensionRegistries {
  const plugin = new AppPlugin();
  plugin.addLink({
    title: LINK_TITLE,
    description: LINK_DESCRIPTION,
    path,
    targets: PluginExtensionPoints.TraceViewResourceAttributes,
    group: { name: ATTRIBUTE_KEY },
    openInNewTab,
  });

  const registries: PluginExtensionRegistries = {
    addedLinksRegistry: new AddedLinksRegistry([]),
    addedComponentsRegistry: new AddedComponentsRegistry([]),
    addedFunctionsRegistry: new AddedFunctionsRegistry([]),
    exposedComponentsRegistry: new ExposedComponentsRegistry([]),
  };
  // pluginImporter registers whatever addLink stored, with no path check of its own.
  registries.addedLinksRegistry.register({
    pluginId: 'installed-app',
    configs: plugin.addedLinkConfigs,
  });
  return registries;
}

function AttributeTable({
  registries,
  openLinksInSameTab,
}: {
  registries: PluginExtensionRegistries;
  openLinksInSameTab: boolean;
}) {
  return (
    <ExtensionRegistriesProvider registries={registries}>
      <ResourceAttributeTable openLinksInSameTab={openLinksInSameTab} />
    </ExtensionRegistriesProvider>
  );
}

function ResourceAttributeTable({ openLinksInSameTab }: { openLinksInSameTab: boolean }): JSX.Element | null {
  const { links, isLoading } = usePluginLinks({
    extensionPointId: PluginExtensionPoints.TraceViewResourceAttributes,
    limitPerPlugin: 15,
    context: {
      attributes: { [ATTRIBUTE_KEY]: [ATTRIBUTE_VALUE] },
    },
  });

  if (isLoading) {
    return null;
  }

  const data = [{ key: ATTRIBUTE_KEY, value: ATTRIBUTE_VALUE }];
  return (
    <KeyValuesTable
      data={data}
      datasourceType="tempo"
      openLinksInSameTab={openLinksInSameTab}
      linksGetter={(pairs, index) => {
        const key = pairs[index]?.key;
        return links.filter((link) => (link.group?.name ?? link.category) === key);
      }}
    />
  );
}

function renderAttributeTable(path: string, openLinksInSameTab: boolean, openInNewTab?: boolean) {
  const registries = registerInstalledAppLink(path, openInNewTab);
  return render(<AttributeTable registries={registries} openLinksInSameTab={openLinksInSameTab} />);
}

function expectAnchorStaysOnThisHost(anchor: HTMLElement) {
  const raw = anchor.getAttribute('href');
  const resolvedHost = raw ? hostOf((anchor as HTMLAnchorElement).href) : pageHost();
  expect(resolvedHost).toBe(pageHost());
}

describe('same-origin trace links with a double-slash path', () => {
  const previousEnv = config.buildInfo.env;

  beforeEach(() => {
    config.buildInfo.env = 'production';
    setReturnToPreviousHook(() => () => undefined);
  });

  afterEach(() => {
    config.buildInfo.env = previousEnv;
    locationService.replace('/');
  });

  describe('getTraceViewLinkAttrs', () => {
    it.each(doubleSlashPaths)('does not return an address on another host for %s', (suffix) => {
      const attrs = getTraceViewLinkAttrs(sameOriginPath(suffix));
      if (attrs) {
        expect(hostOf(attrs.href)).toBe(pageHost());
      } else {
        expect(attrs).toBeUndefined();
      }
    });

    it('keeps an ordinary same-origin path on this host', () => {
      expect(getTraceViewLinkAttrs(sameOriginPath('/a/installed-app'))).toEqual({
        href: '/a/installed-app',
        target: '_self',
      });
    });

    it('still opens a different origin in a new tab', () => {
      expect(getTraceViewLinkAttrs(`https://${ATTACKER_HOST}/phish`)).toEqual({
        href: `https://${ATTACKER_HOST}/phish`,
        target: '_blank',
        rel: 'noopener noreferrer',
      });
    });
  });

  describe('openTraceViewHref', () => {
    it.each(doubleSlashPaths)('does not send the router or a new tab to another host for %s', (suffix) => {
      const openSpy = jest.spyOn(window, 'open').mockImplementation(() => null);

      openTraceViewHref(sameOriginPath(suffix));

      const location = locationService.getLocation();
      expect(hostOf(`${location.pathname}${location.search}${location.hash}`)).toBe(pageHost());
      for (const call of openSpy.mock.calls) {
        expect(hostOf(String(call[0]))).toBe(pageHost());
      }
      openSpy.mockRestore();
    });

    it('still pushes an ordinary same-origin absolute URL', () => {
      openTraceViewHref(sameOriginPath('/a/installed-app'));

      expect(locationService.getLocation().pathname).toBe('/a/installed-app');
    });
  });

  describe('span attribute table', () => {
    it.each(doubleSlashPaths)(
      'does not point the Explore anchor at another host for a plugin link %s',
      (suffix) => {
        renderAttributeTable(sameOriginPath(suffix), true);

        expect(screen.getByText(ATTRIBUTE_VALUE)).toBeInTheDocument();
        expectAnchorStaysOnThisHost(screen.getByTitle(LINK_TITLE));
      }
    );

    it.each(doubleSlashPaths)(
      'does not point the new-tab anchor at another host for a plugin link %s',
      (suffix) => {
        renderAttributeTable(sameOriginPath(suffix), false);

        expect(screen.getByText(ATTRIBUTE_VALUE)).toBeInTheDocument();
        expectAnchorStaysOnThisHost(screen.getByTitle(LINK_TITLE));
      }
    );

    it('does not point the anchor at another host when the plugin sets openInNewTab', () => {
      renderAttributeTable(sameOriginPath(`//${ATTACKER_HOST}/phish`), true, true);

      expectAnchorStaysOnThisHost(screen.getByTitle(LINK_TITLE));
    });

    it('does not leave this host on an unmodified click or a ctrl-click', async () => {
      const user = userEvent.setup();
      renderAttributeTable(sameOriginPath(`//${ATTACKER_HOST}/phish`), true);
      const anchor = screen.getByTitle(LINK_TITLE);

      await user.click(anchor);
      expect(hostOf(`${locationService.getLocation().pathname}${locationService.getLocation().search}`)).toBe(
        pageHost()
      );

      await user.keyboard('{Control>}');
      await user.click(anchor);
      await user.keyboard('{/Control}');

      expectAnchorStaysOnThisHost(anchor);
      expect(window.location.host).toBe(pageHost());
    });

    it('does not point a menu of plugin links at another host', async () => {
      const user = userEvent.setup();
      const plugin = new AppPlugin();
      plugin.addLink({
        title: 'Catalog',
        description: LINK_DESCRIPTION,
        path: sameOriginPath(`//${ATTACKER_HOST}/phish`),
        targets: PluginExtensionPoints.TraceViewResourceAttributes,
        group: { name: ATTRIBUTE_KEY },
      });
      plugin.addLink({
        title: 'Runbook',
        description: 'Open the runbook',
        path: sameOriginPath(`/\\${ATTACKER_HOST}/runbook`),
        targets: PluginExtensionPoints.TraceViewResourceAttributes,
        group: { name: ATTRIBUTE_KEY },
      });
      const registries: PluginExtensionRegistries = {
        addedLinksRegistry: new AddedLinksRegistry([]),
        addedComponentsRegistry: new AddedComponentsRegistry([]),
        addedFunctionsRegistry: new AddedFunctionsRegistry([]),
        exposedComponentsRegistry: new ExposedComponentsRegistry([]),
      };
      registries.addedLinksRegistry.register({
        pluginId: 'installed-app',
        configs: plugin.addedLinkConfigs,
      });

      render(<AttributeTable registries={registries} openLinksInSameTab />);

      await user.click(screen.getByRole('button', { name: ATTRIBUTE_VALUE }));

      const service = await screen.findByRole('menuitem', { name: LINK_DESCRIPTION });
      const runbook = screen.getByRole('menuitem', { name: 'Open the runbook' });
      expectAnchorStaysOnThisHost(service);
      expectAnchorStaysOnThisHost(runbook);
    });

    it('does not follow a configure() path that parses to another host', () => {
      const plugin = new AppPlugin();
      plugin.addLink({
        title: LINK_TITLE,
        description: LINK_DESCRIPTION,
        path: '/a/installed-app',
        targets: PluginExtensionPoints.TraceViewResourceAttributes,
        group: { name: ATTRIBUTE_KEY },
        configure: () => ({ path: sameOriginPath(`//${ATTACKER_HOST}/phish`) }),
      });
      const registries: PluginExtensionRegistries = {
        addedLinksRegistry: new AddedLinksRegistry([]),
        addedComponentsRegistry: new AddedComponentsRegistry([]),
        addedFunctionsRegistry: new AddedFunctionsRegistry([]),
        exposedComponentsRegistry: new ExposedComponentsRegistry([]),
      };
      registries.addedLinksRegistry.register({
        pluginId: 'installed-app',
        configs: plugin.addedLinkConfigs,
      });

      render(<AttributeTable registries={registries} openLinksInSameTab />);

      expectAnchorStaysOnThisHost(screen.getByTitle(LINK_TITLE));
    });

    it('still links an ordinary plugin path inside this server', () => {
      renderAttributeTable(sameOriginPath('/a/installed-app'), true);

      const anchor = screen.getByTitle(LINK_TITLE) as HTMLAnchorElement;
      expect(anchor.getAttribute('href') ?? '').toMatch(/^\/a\/installed-app\?/);
      expect(hostOf(anchor.href)).toBe(pageHost());
      expect(anchor).toHaveAttribute('target', '_self');
    });
  });
});
