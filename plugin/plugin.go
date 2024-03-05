package plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"

	"github.com/carlmjohnson/requests"
	"github.com/corazawaf/libinjection-go"
	sdkAct "github.com/gatewayd-io/gatewayd-plugin-sdk/act"
	"github.com/gatewayd-io/gatewayd-plugin-sdk/databases/postgres"
	sdkPlugin "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin"
	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/spf13/cast"
	"google.golang.org/grpc"
)

type Plugin struct {
	goplugin.GRPCPlugin
	v1.GatewayDPluginServiceServer
	Logger                     hclog.Logger
	Threshold                  float32
	EnableLibinjection         bool
	LibinjectionPermissiveMode bool
	TokenizerAPIAddress        string
	ServingAPIAddress          string
}

type InjectionDetectionPlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	Impl Plugin
}

// GRPCServer registers the plugin with the gRPC server.
func (p *InjectionDetectionPlugin) GRPCServer(b *goplugin.GRPCBroker, s *grpc.Server) error {
	v1.RegisterGatewayDPluginServiceServer(s, &p.Impl)
	return nil
}

// GRPCClient returns the plugin client.
func (p *InjectionDetectionPlugin) GRPCClient(ctx context.Context, b *goplugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return v1.NewGatewayDPluginServiceClient(c), nil
}

// NewInjectionDetectionPlugin returns a new instance of the TestPlugin.
func NewInjectionDetectionPlugin(impl Plugin) *InjectionDetectionPlugin {
	return &InjectionDetectionPlugin{
		NetRPCUnsupportedPlugin: goplugin.NetRPCUnsupportedPlugin{},
		Impl:                    impl,
	}
}

// GetPluginConfig returns the plugin config. This is called by GatewayD
// when the plugin is loaded. The plugin config is used to configure the
// plugin.
func (p *Plugin) GetPluginConfig(ctx context.Context, _ *v1.Struct) (*v1.Struct, error) {
	GetPluginConfig.Inc()

	return v1.NewStruct(PluginConfig)
}

// OnTrafficFromClient is called when a request is received by GatewayD from the client.
// This can be used to modify the request or terminate the connection by returning an error
// or a response.
func (p *Plugin) OnTrafficFromClient(ctx context.Context, req *v1.Struct) (*v1.Struct, error) {
	OnTrafficFromClient.Inc()
	// Handle the client message.
	req, err := postgres.HandleClientMessage(req, p.Logger)
	if err != nil {
		p.Logger.Debug("Failed to handle client message", "error", err)
	}

	// Get the client request from the GatewayD request.
	request := cast.ToString(sdkPlugin.GetAttr(req, "request", ""))
	if request == "" {
		return req, nil
	}

	// Get the query from the request.
	query := cast.ToString(sdkPlugin.GetAttr(req, "query", ""))
	if query == "" {
		p.Logger.Debug("Failed to get query from request, possibly not a SQL query request")
		return req, nil
	}
	p.Logger.Trace("Query", "query", query)

	// Decode the query.
	decodedQuery, err := base64.StdEncoding.DecodeString(query)
	if err != nil {
		return req, err
	}
	p.Logger.Trace("Decoded Query", "decodedQuery", decodedQuery)

	// Unmarshal query into a map.
	var queryMap map[string]interface{}
	if err := json.Unmarshal(decodedQuery, &queryMap); err != nil {
		p.Logger.Error("Failed to unmarshal query", "error", err)
		return req, nil
	}
	queryString := cast.ToString(queryMap["String"])

	var tokens map[string]interface{}
	err = requests.
		URL(p.TokenizerAPIAddress).
		Path("/tokenize_and_sequence").
		BodyJSON(map[string]interface{}{
			"query": queryString,
		}).
		ToJSON(&tokens).
		Fetch(context.Background())
	if err != nil {
		p.Logger.Error("Failed to make POST request", "error", err)
		if p.isSQLi(queryString) && !p.LibinjectionPermissiveMode {
			return p.errorResponse(req, queryString), nil
		}
		return req, nil
	}

	var output map[string]interface{}
	err = requests.
		URL(p.ServingAPIAddress).
		Path("/v1/models/sqli_model:predict").
		BodyJSON(map[string]interface{}{
			"inputs": []interface{}{cast.ToSlice(tokens["tokens"])},
		}).
		ToJSON(&output).
		Fetch(context.Background())
	if err != nil {
		p.Logger.Error("Failed to make POST request", "error", err)
		if p.isSQLi(queryString) && !p.LibinjectionPermissiveMode {
			return p.errorResponse(req, queryString), nil
		}
		return req, nil
	}

	predictions := cast.ToSlice(output["outputs"])
	scores := cast.ToSlice(predictions[0])
	score := cast.ToFloat32(scores[0])
	p.Logger.Trace("Deep learning model prediction", "score", score)

	// Check the prediction against the threshold,
	// otherwise check if the query is an SQL injection using libinjection.
	injection := p.isSQLi(queryString)
	if score >= p.Threshold {
		if p.EnableLibinjection && !injection {
			p.Logger.Debug("False positive detected by libinjection")
		}

		Detections.Inc()
		p.Logger.Warn("SQL injection detected by deep learning model", "score", score)
		return p.errorResponse(req, queryString), nil
	} else if p.EnableLibinjection && injection && !p.LibinjectionPermissiveMode {
		Detections.Inc()
		p.Logger.Warn("SQL injection detected by libinjection")
		return p.errorResponse(req, queryString), nil
	} else {
		p.Logger.Trace("No SQL injection detected")
	}

	return req, nil
}

func (p *Plugin) isSQLi(query string) bool {
	// Check if libinjection is enabled.
	if !p.EnableLibinjection {
		return false
	}

	// Check if the query is an SQL injection using libinjection.
	injection, _ := libinjection.IsSQLi(query)
	if injection {
		p.Logger.Warn("SQL injection detected by libinjection")
	}
	p.Logger.Trace("SQLInjection", "is_injection", cast.ToString(injection))
	return injection
}

func (p *Plugin) errorResponse(req *v1.Struct, queryString string) *v1.Struct {
	Preventions.Inc()

	// Create a PostgreSQL error response.
	errResp := postgres.ErrorResponse(
		"SQL injection detected",
		"EXCEPTION",
		"42000",
		"Back off, you're not welcome here.",
	)

	// Create a ready for query response.
	readyForQuery := &pgproto3.ReadyForQuery{TxStatus: 'I'}
	// TODO: Decide whether to terminate the connection.
	response, err := readyForQuery.Encode(errResp)
	if err != nil {
		p.Logger.Error("Failed to encode ready for query response", "error", err)
		return req
	}

	signals, err := v1.NewList([]any{
		sdkAct.Terminate().ToMap(),
		sdkAct.Log("error", "SQL injection detected", map[string]any{
			"query": queryString,
		}).ToMap(),
	})
	if err != nil {
		p.Logger.Error("Failed to create signals", "error", err)
		return req
	}

	// Create a response to send back to the client.
	req.Fields[sdkAct.Signals] = v1.NewListValue(signals)
	req.Fields["response"] = v1.NewBytesValue(response)
	return req
}
