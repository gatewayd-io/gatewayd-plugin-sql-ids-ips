package plugin

import (
	"github.com/gatewayd-io/gatewayd-plugin-sdk/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// The following metrics are defined in the plugin and are used to
// track the number of times the plugin methods are called. These
// metrics are used as examples to test the plugin metrics functionality.
var (
	GetPluginConfig = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Name:      "get_plugin_config_total",
		Help:      "The total number of calls to the getPluginConfig method",
	})
	OnTrafficFromClient = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Name:      "on_traffic_from_client_total",
		Help:      "The total number of calls to the onTrafficFromClient method",
	})
	Detections = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Name:      "detections_total",
		Help:      "The total number of malicious requests detected",
	})
	Preventions = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: metrics.Namespace,
		Name:      "preventions_total",
		Help:      "The total number of malicious requests prevented",
	})
)
