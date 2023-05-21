package plugin

import (
	sdkConfig "github.com/gatewayd-io/gatewayd-plugin-sdk/config"
	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	goplugin "github.com/hashicorp/go-plugin"
)

var (
	PluginID = v1.PluginID{
		Name:      "gatewayd-plugin-sql-idp",
		Version:   "0.0.1",
		RemoteUrl: "github.com/gatewayd-io/gatewayd-plugin-sql-idp",
	}
	PluginMap = map[string]goplugin.Plugin{
		"gatewayd-plugin-sql-idp": &TemplatePlugin{},
	}
	// TODO: Handle this in a better way
	// https://github.com/gatewayd-io/gatewayd-plugin-sdk/issues/3
	PluginConfig = map[string]interface{}{
		"id": map[string]interface{}{
			"name":      PluginID.Name,
			"version":   PluginID.Version,
			"remoteUrl": PluginID.RemoteUrl,
		},
		"description": "Template plugin",
		"authors": []interface{}{
			"Mostafa Moradian <mostafa@gatewayd.io>",
		},
		"license":    "Apache 2.0",
		"projectUrl": "https://github.com/gatewayd-io/gatewayd-plugin-sql-idp",
		// Compile-time configuration
		"config": map[string]interface{}{
			"metricsEnabled": sdkConfig.GetEnv("METRICS_ENABLED", "true"),
			"metricsUnixDomainSocket": sdkConfig.GetEnv(
				"METRICS_UNIX_DOMAIN_SOCKET", "/tmp/gatewayd-plugin-sql-idp.sock"),
			"metricsEndpoint": sdkConfig.GetEnv("METRICS_ENDPOINT", "/metrics"),
			"threshold":       sdkConfig.GetEnv("THRESHOLD", "0.8"),
			"modelPath":       sdkConfig.GetEnv("MODEL_PATH", "sqli_model"),
		},
		"hooks": []interface{}{
			// Converting HookName to int32 is required because the plugin
			// framework doesn't support enums.	See:
			// https://github.com/gatewayd-io/gatewayd-plugin-sdk/issues/3
			int32(v1.HookName_HOOK_NAME_ON_TRAFFIC_FROM_CLIENT),
		},
		"tags":       []interface{}{"plugin", "sql", "idp"},
		"categories": []interface{}{"plugin", "enterprise"},
	}
)
