package supportbundlesimpl

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"time"

	"gopkg.in/ini.v1"

	"github.com/grafana/grafana/pkg/infra/log"
	"github.com/grafana/grafana/pkg/plugins"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginsettings"
	"github.com/grafana/grafana/pkg/services/pluginsintegration/pluginstore"
	"github.com/grafana/grafana/pkg/services/supportbundles"
	"github.com/grafana/grafana/pkg/setting"
)

func basicCollector(cfg *setting.Cfg) supportbundles.Collector {
	return supportbundles.Collector{
		UID:               "basic",
		DisplayName:       "Basic information",
		Description:       "Basic information about the Grafana instance",
		IncludedByDefault: true,
		Default:           true,
		Fn: func(ctx context.Context) (*supportbundles.SupportItem, error) {
			type basicInfo struct {
				Version         string    `json:"version"`          // Version is the version of Grafana instance.
				Commit          string    `json:"commit"`           // Commit is the commit hash of the Grafana instance.
				CollectionDate  time.Time `json:"collection_date"`  // CollectionDate is the date when the support bundle was created.
				DefaultTimezone string    `json:"default_timezone"` // DefaultTimezone is the default timezone of the Grafana instance.
				Alloc           uint64    `json:"alloc"`            // Alloc is bytes of allocated heap objects.
				TotalAlloc      uint64    `json:"total_alloc"`      // TotalAlloc is cumulative bytes allocated for heap objects.
				Sys             uint64    `json:"sys"`              // Sys is the total bytes of memory obtained from the OS.
				Mallocs         uint64    `json:"mallocs"`          // Mallocs is the cumulative count of heap objects allocated.
				Frees           uint64    `json:"frees"`            // Frees is the cumulative count of heap objects freed.
				NumGC           uint32    `json:"num_gc"`           // NumGC is the number of completed GC cycles.
				PauseTotalNs    uint64    `json:"pause_total_ns"`   // PauseTotalNs is the cumulative nanoseconds in GC
				NumCPU          int       `json:"num_cpu"`          // NumCPU is the number of logical CPUs usable by the current process.
				NumGoRoutines   int       `json:"num_go_routines"`  // NumGoRoutines is the number of goroutines that currently exist.
				GoVersion       string    `json:"go_version"`       // GoVersion is the version of Go used to build the binary.
				GoOS            string    `json:"go_os"`            // GoOS is the operating system target used to build the binary.
				GoArch          string    `json:"go_arch"`          // GoArch is the architecture target used to build the binary.
				GoCompiler      string    `json:"go_compiler"`      // GoCompiler is the compiler used to build the binary.
			}

			memstats := runtime.MemStats{}
			runtime.ReadMemStats(&memstats)

			collectionDate := time.Now()
			tz, offset := collectionDate.Zone()

			loc, _ := time.LoadLocation("UTC")
			now := collectionDate.In(loc)

			info := basicInfo{
				Version:         cfg.BuildVersion,
				Commit:          cfg.BuildCommit,
				CollectionDate:  now,
				DefaultTimezone: fmt.Sprintf("%s (UTC%+d)", tz, offset/60/60),
				Alloc:           memstats.Alloc,
				TotalAlloc:      memstats.TotalAlloc,
				Sys:             memstats.Sys,
				Mallocs:         memstats.Mallocs,
				Frees:           memstats.Frees,
				NumGC:           memstats.NumGC,
				PauseTotalNs:    memstats.PauseTotalNs,
				NumCPU:          runtime.NumCPU(),
				NumGoRoutines:   runtime.NumGoroutine(),
				GoVersion:       runtime.Version(),
				GoOS:            runtime.GOOS,
				GoArch:          runtime.GOARCH,
				GoCompiler:      runtime.Compiler,
			}
			data, err := json.MarshalIndent(info, "", " ")
			if err != nil {
				return nil, err
			}

			return &supportbundles.SupportItem{
				Filename:  "basic.json",
				FileBytes: data,
			}, nil
		},
	}
}

func settingsCollector(settings setting.Provider) supportbundles.Collector {
	return supportbundles.Collector{
		UID:               "settings",
		DisplayName:       "Settings",
		Description:       "Settings of the Grafana instance",
		IncludedByDefault: false,
		Default:           true,
		Fn: func(ctx context.Context) (*supportbundles.SupportItem, error) {
			data, err := json.MarshalIndent(supportBundleSettings(settings.Current()), "", " ")
			if err != nil {
				return nil, err
			}

			return &supportbundles.SupportItem{
				Filename:  "settings.json",
				FileBytes: data,
			}, nil
		},
	}
}

// supportBundleSettingsAllowlist lists the non-boolean settings whose values
// are copied into a support bundle. Settings.Current only redacts keys whose
// names match known credential patterns, which misses many credential keys,
// so every value not listed here is masked instead.
var supportBundleSettingsAllowlist = map[string]map[string]struct{}{
	ini.DefaultSection: keySet("app_mode", "target"),
	"paths":            keySet("data", "temp_data_lifetime", "logs", "plugins", "bundled_plugins", "provisioning"),
	"server":           keySet("protocol", "min_tls_version", "http_addr", "http_port", "domain", "static_root_path", "read_timeout"),
	"database":         keySet("type", "max_idle_conn", "max_open_conn", "conn_max_lifetime", "ssl_mode", "isolation_level", "cache_mode", "locking_attempt_timeout_sec", "query_retries", "transaction_retries"),
	"remote_cache":     keySet("type"),
	"dataproxy":        keySet("timeout", "dialTimeout", "keep_alive_seconds", "tls_handshake_timeout_seconds", "expect_continue_timeout_seconds", "max_conns_per_host", "max_idle_connections", "idle_conn_timeout_seconds", "response_limit", "row_limit"),
	"log":              keySet("mode", "level", "filters"),
	"log.console":      keySet("level", "format"),
	"log.file":         keySet("level", "format", "max_lines", "max_size_shift", "max_days"),
	"feature_toggles":  keySet("enable"),
	"plugins":          keySet("allow_loading_unsigned_plugins", "disable_plugins", "update_strategy"),
	"unified_alerting": keySet("initialization_timeout", "admin_config_poll_interval", "alertmanager_config_poll_interval", "evaluation_timeout", "max_attempts", "min_interval"),
	"live":             keySet("max_connections", "message_size_limit", "client_queue_max_size", "ha_engine"),
}

func keySet(keys ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(keys))
	for _, k := range keys {
		set[k] = struct{}{}
	}
	return set
}

func supportBundleSettings(current setting.SettingsBag) setting.SettingsBag {
	out := make(setting.SettingsBag, len(current))
	for section, keys := range current {
		out[section] = make(map[string]string, len(keys))
		for key, value := range keys {
			out[section][key] = supportBundleSettingValue(section, key, value)
		}
	}
	return out
}

func supportBundleSettingValue(section, key, value string) string {
	if value == "" || value == setting.RedactedPassword || strings.EqualFold(value, "true") || strings.EqualFold(value, "false") {
		return value
	}
	if _, ok := supportBundleSettingsAllowlist[section][key]; ok {
		return value
	}
	return setting.RedactedPassword
}

func pluginInfoCollector(pluginStore pluginstore.Store, pluginSettings pluginsettings.Service, logger log.Logger) supportbundles.Collector {
	return supportbundles.Collector{
		UID:               "plugins",
		DisplayName:       "Plugin information",
		Description:       "Plugin information for the Grafana instance",
		IncludedByDefault: false,
		Default:           true,
		Fn: func(ctx context.Context) (*supportbundles.SupportItem, error) {
			type PluginInfo struct {
				id          string
				Name        string
				Description string
				PluginType  string `json:"type"`

				Author          plugins.InfoLink `json:"author,omitempty"`
				SignatureStatus plugins.SignatureStatus
				SignatureType   plugins.SignatureType
				SignatureOrg    string

				GrafanaVersionDependency string `json:"grafanaVersionDependency,omitempty"`

				Settings []pluginsettings.InfoDTO `json:"settings,omitempty"`
			}

			// plugin definitions
			plugins := pluginStore.Plugins(ctx)

			// plugin settings
			settings, err := pluginSettings.GetPluginSettings(ctx, &pluginsettings.GetArgs{})
			if err != nil {
				logger.Debug("Failed to fetch plugin settings:", "err", err)
			}

			settingMap := make(map[string][]*pluginsettings.InfoDTO)
			for _, ps := range settings {
				settingMap[ps.PluginID] = append(settingMap[ps.PluginID], ps)
			}

			var pluginInfoList []PluginInfo
			for _, plugin := range plugins {
				// skip builtin and core plugins
				if plugin.BuiltIn || plugin.IsCorePlugin() {
					continue
				}
				// skip plugins that are included in another plugin
				if plugin.IncludedInAppID != "" {
					continue
				}

				pInfo := PluginInfo{
					id:                       plugin.ID,
					Name:                     plugin.Name,
					Description:              plugin.Info.Description,
					PluginType:               string(plugin.Type),
					Author:                   plugin.Info.Author,
					SignatureStatus:          plugin.Signature,
					SignatureType:            plugin.SignatureType,
					SignatureOrg:             plugin.SignatureOrg,
					GrafanaVersionDependency: plugin.Dependencies.GrafanaVersion,
				}

				for _, ps := range settingMap[plugin.ID] {
					pInfo.Settings = append(pInfo.Settings, pluginsettings.InfoDTO{
						OrgID:         ps.OrgID,
						Enabled:       ps.Enabled,
						PluginVersion: ps.PluginVersion,
					})
				}

				pluginInfoList = append(pluginInfoList, pInfo)
			}

			data, err := json.MarshalIndent(pluginInfoList, "", " ")
			if err != nil {
				return nil, err
			}
			return &supportbundles.SupportItem{
				Filename:  "plugins.json",
				FileBytes: data,
			}, nil
		},
	}
}
