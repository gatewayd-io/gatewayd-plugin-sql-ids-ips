package main

import (
	"flag"
	"log"
	"os"

	sdkConfig "github.com/gatewayd-io/gatewayd-plugin-sdk/config"
	"github.com/gatewayd-io/gatewayd-plugin-sdk/logging"
	"github.com/gatewayd-io/gatewayd-plugin-sdk/metrics"
	p "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin"
	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	"github.com/gatewayd-io/gatewayd-plugin-sql-ids-ips/plugin"
	"github.com/getsentry/sentry-go"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/spf13/cast"
)

func main() {
	sentryDSN := sdkConfig.GetEnv("SENTRY_DSN", "")
	// Initialize Sentry SDK
	err := sentry.Init(sentry.ClientOptions{
		Dsn:              sentryDSN,
		TracesSampleRate: 1.0,
	})
	if err != nil {
		log.Fatalf("Failed to initialize Sentry SDK: %s", err.Error())
	}

	// Parse command line flags, passed by GatewayD via the plugin config
	logLevel := flag.String("log-level", "info", "Log level")
	flag.Parse()

	logger := hclog.New(&hclog.LoggerOptions{
		Level:      logging.GetLogLevel(*logLevel),
		Output:     os.Stderr,
		JSONFormat: true,
		Color:      hclog.ColorOff,
	})

	pluginInstance := plugin.NewInjectionDetectionPlugin(plugin.Plugin{
		Logger: logger,
	})

	var metricsConfig *metrics.MetricsConfig
	if cfg := cast.ToStringMap(plugin.PluginConfig["config"]); cfg != nil {
		metricsConfig = metrics.NewMetricsConfig(cfg)
		if metricsConfig != nil && metricsConfig.Enabled {
			go metrics.ExposeMetrics(metricsConfig, logger)
		}

		pluginInstance.Impl.Threshold = cast.ToFloat32(cfg["threshold"])
		pluginInstance.Impl.EnableLibinjection = cast.ToBool(cfg["enableLibinjection"])
		pluginInstance.Impl.LibinjectionPermissiveMode = cast.ToBool(
			cfg["libinjectionPermissiveMode"])
		pluginInstance.Impl.PredictionAPIAddress = cast.ToString(cfg["predictionAPIAddress"])

		pluginInstance.Impl.ResponseType = cast.ToString(cfg["responseType"])
		pluginInstance.Impl.ErrorMessage = cast.ToString(cfg["errorMessage"])
		pluginInstance.Impl.ErrorSeverity = cast.ToString(cfg["errorSeverity"])
		pluginInstance.Impl.ErrorNumber = cast.ToString(cfg["errorNumber"])
		pluginInstance.Impl.ErrorDetail = cast.ToString(cfg["errorDetail"])
		pluginInstance.Impl.LogLevel = cast.ToString(cfg["logLevel"])
	}

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: goplugin.HandshakeConfig{
			ProtocolVersion:  1,
			MagicCookieKey:   sdkConfig.GetEnv("MAGIC_COOKIE_KEY", ""),
			MagicCookieValue: sdkConfig.GetEnv("MAGIC_COOKIE_VALUE", ""),
		},
		Plugins: v1.GetPluginSetMap(map[string]goplugin.Plugin{
			plugin.PluginID.Name: pluginInstance,
		}),
		GRPCServer: p.DefaultGRPCServer,
		Logger:     logger,
	})
}
