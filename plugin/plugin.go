package plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/corazawaf/libinjection-go"
	tf "github.com/galeone/tensorflow/tensorflow/go"
	"github.com/gatewayd-io/gatewayd-plugin-sdk/databases/postgres"
	sdkPlugin "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin"
	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/jackc/pgx/pgproto3"
	"github.com/spf13/cast"
	"google.golang.org/grpc"
)

type Plugin struct {
	goplugin.GRPCPlugin
	v1.GatewayDPluginServiceServer
	Logger                     hclog.Logger
	Model                      *tf.SavedModel
	Threshold                  float32
	EnableLibinjection         bool
	LibinjectionPermissiveMode bool
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

// NewTemplatePlugin returns a new instance of the TestPlugin.
func NewTemplatePlugin(impl Plugin) *InjectionDetectionPlugin {
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

	isSQLi := func(query string) bool {
		// Check if libinjection is enabled.
		if !p.EnableLibinjection {
			return false
		}

		// Check if the query is an SQL injection using libinjection.
		injection, _ := libinjection.IsSQLi(query)
		if injection {
			Detections.Inc()
			p.Logger.Warn("SQL injection detected by libinjection")
		}
		p.Logger.Trace("SQLInjection", "is_injection", cast.ToString(injection))
		return injection
	}

	errorResponse := func() *v1.Struct {
		Preventions.Inc()

		// Create a PostgreSQL error response.
		errResp := &pgproto3.ErrorResponse{
			Severity: "EXCEPTION",
			Message:  "SQL injection detected",
			Detail:   "Back off, you're not welcome here.",
			Code:     "42000",
		}

		// Create a ready for query response.
		readyForQuery := &pgproto3.ReadyForQuery{TxStatus: 'I'}

		// Create a buffer to write the response to.
		response := errResp.Encode(nil)
		// TODO: Decide whether to terminate the connection.
		response = readyForQuery.Encode(response)

		// Create a response to send back to the client.
		req.Fields["response"] = v1.NewBytesValue(response)
		req.Fields["terminate"] = v1.NewBoolValue(true)

		return req
	}

	// Make an HTTP GET request to the tokenize service.
	resp, err := http.Get(
		fmt.Sprintf("http://localhost:5000/tokenize_and_sequence/%s", queryString))
	if err != nil {
		p.Logger.Error("Failed to make GET request", "error", err)
		if isSQLi(queryString) && !p.LibinjectionPermissiveMode {
			return errorResponse(), nil
		}
		return req, nil
	}

	// Read the response body.
	defer resp.Body.Close()
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		p.Logger.Error("Failed to decode response body", "error", err)
		if isSQLi(queryString) && !p.LibinjectionPermissiveMode {
			return errorResponse(), nil
		}
		return req, nil
	}

	// Get the tokens from the response.
	var tokens []float32
	for _, v := range data["tokens"].([]interface{}) {
		tokens = append(tokens, cast.ToFloat32(v))
	}

	// Convert []float32 to a [][]float32.
	allTokens := make([][]float32, 1)
	allTokens[0] = tokens

	p.Logger.Trace("Tokens", "tokens", allTokens)

	// Create a tensor from the tokens.
	inputTensor, err := tf.NewTensor(allTokens)
	if err != nil {
		p.Logger.Error("Failed to create input tensor", "error", err)
		if isSQLi(queryString) && !p.LibinjectionPermissiveMode {
			return errorResponse(), nil
		}
		return req, nil
	}

	// Run the model to predict if the query is malicious or not.
	output, err := p.Model.Session.Run(
		map[tf.Output]*tf.Tensor{
			p.Model.Graph.Operation("serving_default_embedding_input").Output(0): inputTensor,
		},
		[]tf.Output{
			p.Model.Graph.Operation("StatefulPartitionedCall").Output(0),
		},
		nil,
	)
	if err != nil {
		p.Logger.Error("Failed to run model", "error", err)
		if isSQLi(queryString) && !p.LibinjectionPermissiveMode {
			return errorResponse(), nil
		}
		return req, nil
	}
	predictions := output[0].Value().([][]float32)
	score := predictions[0][0]
	p.Logger.Trace("Deep learning model prediction", "score", score)

	// Check the prediction against the threshold,
	// otherwise check if the query is an SQL injection using libinjection.
	injection := isSQLi(queryString)
	if score >= p.Threshold {
		if p.EnableLibinjection && !injection {
			p.Logger.Debug("False positive detected by libinjection")
		}

		Detections.Inc()
		p.Logger.Warn("SQL injection detected by deep learning model", "score", score)
		return errorResponse(), nil
	} else if p.EnableLibinjection && injection && !p.LibinjectionPermissiveMode {
		Detections.Inc()
		p.Logger.Warn("SQL injection detected by libinjection")
		return errorResponse(), nil
	} else {
		p.Logger.Trace("No SQL injection detected")
	}

	return req, nil
}
