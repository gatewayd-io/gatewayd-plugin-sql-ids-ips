package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"

	tf "github.com/galeone/tensorflow/tensorflow/go"
	"github.com/gatewayd-io/gatewayd-plugin-sdk/databases/postgres"
	sdkPlugin "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin"
	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
	"github.com/jackc/pgx/pgproto3"
	"github.com/spf13/cast"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"
)

type Plugin struct {
	goplugin.GRPCPlugin
	v1.GatewayDPluginServiceServer
	Logger hclog.Logger
}

type TemplatePlugin struct {
	goplugin.NetRPCUnsupportedPlugin
	Impl Plugin
}

// GRPCServer registers the plugin with the gRPC server.
func (p *TemplatePlugin) GRPCServer(b *goplugin.GRPCBroker, s *grpc.Server) error {
	v1.RegisterGatewayDPluginServiceServer(s, &p.Impl)
	return nil
}

// GRPCClient returns the plugin client.
func (p *TemplatePlugin) GRPCClient(ctx context.Context, b *goplugin.GRPCBroker, c *grpc.ClientConn) (interface{}, error) {
	return v1.NewGatewayDPluginServiceClient(c), nil
}

// NewTemplatePlugin returns a new instance of the TestPlugin.
func NewTemplatePlugin(impl Plugin) *TemplatePlugin {
	return &TemplatePlugin{
		NetRPCUnsupportedPlugin: goplugin.NetRPCUnsupportedPlugin{},
		Impl:                    impl,
	}
}

// GetPluginConfig returns the plugin config. This is called by GatewayD
// when the plugin is loaded. The plugin config is used to configure the
// plugin.
func (p *Plugin) GetPluginConfig(
	ctx context.Context, _ *structpb.Struct) (*structpb.Struct, error) {
	GetPluginConfig.Inc()

	return structpb.NewStruct(PluginConfig)
}

// OnTrafficFromClient is called when a request is received by GatewayD from the client.
// This can be used to modify the request or terminate the connection by returning an error
// or a response.
func (p *Plugin) OnTrafficFromClient(
	ctx context.Context, req *structpb.Struct) (*structpb.Struct, error) {
	OnTrafficFromClient.Inc()
	req, err := postgres.HandleClientMessage(req, p.Logger)
	if err != nil {
		p.Logger.Info("Failed to handle client message", "error", err)
	}

	request := cast.ToString(sdkPlugin.GetAttr(req, "request", ""))
	if request == "" {
		return req, nil
	}

	query, err := postgres.GetQueryFromRequest(request)
	if err != nil {
		p.Logger.Error("Failed to get query from request", "error", err)
		return req, nil
	}
	p.Logger.Info("Query", "query", query)

	model, err := tf.LoadSavedModel("sqli_model", []string{"serve"}, nil)
	if err != nil {
		p.Logger.Error("Failed to load model", "error", err)
		return req, nil
	}
	defer model.Session.Close()

	// Create the JSON body from the map.
	body, err := json.Marshal(map[string]interface{}{
		"query": query,
	})
	if err != nil {
		p.Logger.Error("Failed to marshal query", "error", err)
		return req, nil
	}

	// Make an HTTP POST request to the tokenize service.
	resp, err := http.Post(
		"http://localhost:5000/tokenize_and_sequence", "application/json", bytes.NewBuffer(body))
	if err != nil {
		p.Logger.Error("Failed to make POST request", "error", err)
		return req, nil
	}

	// Read the response body.
	defer resp.Body.Close()
	var data map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		p.Logger.Error("Failed to decode response body", "error", err)
		return req, nil

	}

	var tokens []float32
	for _, v := range data["tokens"].([]interface{}) {
		tokens = append(tokens, cast.ToFloat32(v))
	}

	// Convert []float32 to a [][]float32.
	allTokens := make([][]float32, 1)
	allTokens[0] = tokens

	p.Logger.Info("Tokens", "tokens", allTokens)

	inputTensor, err := tf.NewTensor(allTokens)
	if err != nil {
		p.Logger.Error("Failed to create input tensor", "error", err)
		return req, nil
	}

	output, err := model.Session.Run(
		map[tf.Output]*tf.Tensor{
			model.Graph.Operation("serving_default_embedding_input").Output(0): inputTensor,
		},
		[]tf.Output{
			model.Graph.Operation("StatefulPartitionedCall").Output(0),
		},
		nil,
	)
	if err != nil {
		p.Logger.Error("Failed to run model", "error", err)
		return req, nil
	}

	predictions := output[0].Value().([][]float32)
	// Define the threshold for the prediction.
	p.Logger.Info("Prediction", "prediction", predictions[0][0])
	if predictions[0][0] > 0.8 {
		p.Logger.Info("SQL Injection Detected", "prediction", predictions[0][0])

		// Create a PostgreSQL error response.
		errResp := &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Message:  "SQL Injection Detected",
			Detail:   "Back off, you're not welcome here.",
		}

		return structpb.NewStruct(map[string]interface{}{
			"terminate": true,
			"response":  errResp.Encode(nil),
		})
	}

	return req, nil
}
