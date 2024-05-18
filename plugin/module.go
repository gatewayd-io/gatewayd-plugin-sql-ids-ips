package plugin

import (
	sdkConfig "github.com/gatewayd-io/gatewayd-plugin-sdk/config"
	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	goplugin "github.com/hashicorp/go-plugin"
)

var (
	Version  = "0.0.0"
	PluginID = v1.PluginID{
		Name:      "gatewayd-plugin-sql-ids-ips",
		Version:   Version,
		RemoteUrl: "github.com/gatewayd-io/gatewayd-plugin-sql-ids-ips",
	}
	PluginMap = map[string]goplugin.Plugin{
		"gatewayd-plugin-sql-ids-ips": &InjectionDetectionPlugin{},
	}
	// TODO: Handle this in a better way
	// https://github.com/gatewayd-io/gatewayd-plugin-sdk/issues/3
	PluginConfig = map[string]interface{}{
		"id": map[string]interface{}{
			"name":      PluginID.Name,
			"version":   PluginID.Version,
			"remoteUrl": PluginID.RemoteUrl,
		},
		"description": "GatewayD plugin for detection and prevention of SQL injection attacks",
		"authors": []interface{}{
			"Mostafa Moradian <mostafa@gatewayd.io>",
		},
		"license":    "AGPL-3.0",
		"projectUrl": "https://github.com/gatewayd-io/gatewayd-plugin-sql-ids-ips",
		// Compile-time configuration
		"config": map[string]interface{}{
			"metricsEnabled": sdkConfig.GetEnv("METRICS_ENABLED", "true"),
			"metricsUnixDomainSocket": sdkConfig.GetEnv(
				"METRICS_UNIX_DOMAIN_SOCKET", "/tmp/gatewayd-plugin-sql-ids-ips.sock"),
			"metricsEndpoint": sdkConfig.GetEnv("METRICS_ENDPOINT", "/metrics"),
			"tokenizerAPIAddress": sdkConfig.GetEnv(
				"TOKENIZER_API_ADDRESS", "http://localhost:8000"),
			"servingAPIAddress": sdkConfig.GetEnv(
				"SERVING_API_ADDRESS", "http://localhost:8501"),
			"modelName":                  sdkConfig.GetEnv("MODEL_NAME", "sqli_model"),
			"modelVersion":               sdkConfig.GetEnv("MODEL_VERSION", "1"),
			"threshold":                  sdkConfig.GetEnv("THRESHOLD", "0.8"),
			"enableLibinjection":         sdkConfig.GetEnv("ENABLE_LIBINJECTION", "true"),
			"libinjectionPermissiveMode": sdkConfig.GetEnv("LIBINJECTION_MODE", "true"),

			// Possible values: error or empty
			"responseType": sdkConfig.GetEnv("RESPONSE_TYPE", ResponseType),

			// This is part of the error response and the audit trail
			"errorMessage": sdkConfig.GetEnv("ERROR_MESSAGE", ErrorMessage),

			// Response type: error
			// Possible severity values: DEBUG, LOG, INFO, NOTICE, WARNING, and EXCEPTION
			"errorSeverity": sdkConfig.GetEnv("ERROR_SEVERITY", ErrorSeverity),
			"errorNumber":   sdkConfig.GetEnv("ERROR_NUMBER", ErrorNumber),
			"errorDetail":   sdkConfig.GetEnv("ERROR_DETAIL", ErrorDetail),

			// Log an audit trail
			"logLevel": sdkConfig.GetEnv("LOG_LEVEL", LogLevel),
		},
		"hooks": []interface{}{
			// Converting HookName to int32 is required because the plugin
			// framework doesn't support enums.	See:
			// https://github.com/gatewayd-io/gatewayd-plugin-sdk/issues/3
			int32(v1.HookName_HOOK_NAME_ON_TRAFFIC_FROM_CLIENT),
		},
		"tags":       []interface{}{"plugin", "sql", "ids", "ips", "security", "waf"},
		"categories": []interface{}{"plugin", "enterprise"},
	}
)
