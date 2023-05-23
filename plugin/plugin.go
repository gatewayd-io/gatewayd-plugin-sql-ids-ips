package plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	Logger    hclog.Logger
	Model     *tf.SavedModel
	Threshold float32
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

	// Make an HTTP GET request to the tokenize service.
	resp, err := http.Get(
		fmt.Sprintf("http://localhost:5000/tokenize_and_sequence/%s", queryMap["String"]))
	if err != nil {
		p.Logger.Error("Failed to make GET request", "error", err)
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

	p.Logger.Trace("Tokens", "tokens", allTokens)

	inputTensor, err := tf.NewTensor(allTokens)
	if err != nil {
		p.Logger.Error("Failed to create input tensor", "error", err)
		return req, nil
	}

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
		return req, nil
	}

	predictions := output[0].Value().([][]float32)
	// Define the threshold for the prediction.
	p.Logger.Debug("Prediction", "prediction", predictions[0][0])
	if predictions[0][0] >= p.Threshold {
		p.Logger.Warn("SQL Injection Detected", "prediction", predictions[0][0])

		// Create a PostgreSQL error response.
		errResp := &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Message:  "SQL Injection Detected",
			Detail:   "Back off, you're not welcome here.",
		}

		// Create a ready for query response.
		readyForQuery := &pgproto3.ReadyForQuery{TxStatus: 'I'}

		// Create a buffer to write the response to.
		response := errResp.Encode(nil)
		// TODO: Decide whether to terminate the connection.
		response = readyForQuery.Encode(response)

		// Create a response to send back to the client.
		req.Fields["response"] = structpb.NewStringValue(
			base64.StdEncoding.EncodeToString(response))
		req.Fields["terminate"] = structpb.NewBoolValue(true)
		return req, nil
	}

	return req, nil
}
