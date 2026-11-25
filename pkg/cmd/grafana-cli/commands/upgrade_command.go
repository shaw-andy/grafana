package commands

import (
	"context"
	"errors"
	"fmt"

	"github.com/fatih/color"

	"github.com/grafana/grafana/pkg/cmd/grafana-cli/logger"
	"github.com/grafana/grafana/pkg/cmd/grafana-cli/services"
	"github.com/grafana/grafana/pkg/cmd/grafana-cli/utils"
)

func upgradeCommand(c utils.CommandLine) error {
	ctx := context.Background()
	pluginsDir := c.PluginDirectory()
	pluginID := c.Args().First()
	if pluginID == "" {
		return errors.New("please specify plugin to update")
	}

	localPlugin, err := services.GetLocalPlugin(pluginsDir, pluginID)
	if err != nil {
		return err
	}

	plugin, err := services.GetPluginInfoFromRepo(pluginID, c.PluginRepoURL())
	if err != nil {
		return err
	}

	if shouldUpgrade(localPlugin, plugin) {
		opts := newInstallPluginOpts(c)
		opts.beforeExtract = func() error {
			if err := uninstallPlugin(ctx, pluginID, c); err != nil {
				return fmt.Errorf("failed to remove plugin '%s': %w", pluginID, err)
			}
			return nil
		}

		err = installPlugin(ctx, pluginID, "", opts)
		if err == nil {
			logRestartNotice()
		}
		return err
	}

	logger.Infof("%s %s is up to date \n", color.GreenString("✔"), pluginID)
	return nil
}
