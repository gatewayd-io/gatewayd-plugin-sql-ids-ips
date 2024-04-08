package plugin

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

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

const (
	DecodedQueryField string = "decodedQuery"
	DetectorField     string = "detector"
	ScoreField        string = "score"
	QueryField        string = "query"
	ErrorField        string = "error"
	IsInjectionField  string = "is_injection"
	ResponseField     string = "response"
	OutputsField      string = "outputs"
	TokensField       string = "tokens"
	StringField       string = "String"

	DeepLearningModel string = "deep_learning_model"
	Libinjection      string = "libinjection"

	ErrorLevel           string = "error"
	ExceptionLevel       string = "EXCEPTION"
	ErrorNumber          string = "42000"
	DetectionMessage     string = "SQL injection detected"
	ErrorResponseMessage string = "Back off, you're not welcome here."

	TokenizeAndSequencePath string = "/tokenize_and_sequence"
	PredictPath             string = "/v1/models/%s/versions/%s:predict"
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
	ModelName                  string
	ModelVersion               string
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
func (p *InjectionDetectionPlugin) GRPCClient(
	ctx context.Context, b *goplugin.GRPCBroker, c *grpc.ClientConn,
) (any, error) {
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
		p.Logger.Debug("Failed to handle client message", ErrorField, err)
		return req, err
	}

	// Get the query from the request.
	query := cast.ToString(sdkPlugin.GetAttr(req, QueryField, ""))
	if query == "" {
		p.Logger.Debug("Failed to get query from request, possibly not a SQL query request")
		return req, nil
	}
	p.Logger.Trace("Query", QueryField, query)

	// Decode the query.
	decodedQuery, err := base64.StdEncoding.DecodeString(query)
	if err != nil {
		return req, err
	}
	p.Logger.Trace("Decoded Query", DecodedQueryField, decodedQuery)

	// Unmarshal query into a map.
	var queryMap map[string]any
	if err := json.Unmarshal(decodedQuery, &queryMap); err != nil {
		p.Logger.Error("Failed to unmarshal query", ErrorField, err)
		return req, nil
	}
	queryString := cast.ToString(queryMap[StringField])

	var tokens map[string]any
	err = requests.
		URL(p.TokenizerAPIAddress).
		Path(TokenizeAndSequencePath).
		BodyJSON(map[string]any{
			QueryField: queryString,
		}).
		ToJSON(&tokens).
		Fetch(context.Background())
	if err != nil {
		p.Logger.Error("Failed to make POST request", ErrorField, err)
		if p.isSQLi(queryString) && !p.LibinjectionPermissiveMode {
			return p.errorResponse(
				req,
				map[string]any{
					QueryField:    queryString,
					DetectorField: Libinjection,
					ErrorField:    "Failed to make POST request to tokenizer API",
				},
			), nil
		}
		return req, nil
	}

	var output map[string]any
	err = requests.
		URL(p.ServingAPIAddress).
		Path(fmt.Sprintf(PredictPath, p.ModelName, p.ModelVersion)).
		BodyJSON(map[string]any{
			"inputs": []any{cast.ToSlice(tokens[TokensField])},
		}).
		ToJSON(&output).
		Fetch(context.Background())
	if err != nil {
		p.Logger.Error("Failed to make POST request", ErrorField, err)
		if p.isSQLi(queryString) && !p.LibinjectionPermissiveMode {
			return p.errorResponse(
				req,
				map[string]any{
					QueryField:    queryString,
					DetectorField: Libinjection,
					ErrorField:    "Failed to make POST request to serving API",
				},
			), nil
		}
		return req, nil
	}

	predictions := cast.ToSlice(output[OutputsField])
	scores := cast.ToSlice(predictions[0])
	score := cast.ToFloat32(scores[0])
	p.Logger.Trace("Deep learning model prediction", ScoreField, score)

	// Check the prediction against the threshold,
	// otherwise check if the query is an SQL injection using libinjection.
	injection := p.isSQLi(queryString)
	if score >= p.Threshold {
		if p.EnableLibinjection && !injection {
			p.Logger.Debug("False positive detected", DetectorField, Libinjection)
		}

		Detections.With(map[string]string{DetectorField: DeepLearningModel}).Inc()
		p.Logger.Warn(DetectionMessage, ScoreField, score, DetectorField, DeepLearningModel)
		return p.errorResponse(
			req,
			map[string]any{
				QueryField:    queryString,
				ScoreField:    score,
				DetectorField: DeepLearningModel,
			},
		), nil
	} else if p.EnableLibinjection && injection && !p.LibinjectionPermissiveMode {
		Detections.With(map[string]string{DetectorField: Libinjection}).Inc()
		p.Logger.Warn(DetectionMessage, DetectorField, Libinjection)
		return p.errorResponse(
			req,
			map[string]any{
				QueryField:    queryString,
				DetectorField: Libinjection,
			},
		), nil
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
		p.Logger.Warn(DetectionMessage, DetectorField, Libinjection)
	}
	p.Logger.Trace("SQLInjection", IsInjectionField, cast.ToString(injection))
	return injection
}

func (p *Plugin) errorResponse(req *v1.Struct, fields map[string]any) *v1.Struct {
	Preventions.Inc()

	// Create a PostgreSQL error response.
	errResp := postgres.ErrorResponse(
		DetectionMessage,
		ExceptionLevel,
		ErrorNumber,
		ErrorResponseMessage,
	)

	// Create a ready for query response.
	readyForQuery := &pgproto3.ReadyForQuery{TxStatus: 'I'}
	// TODO: Decide whether to terminate the connection.
	response, err := readyForQuery.Encode(errResp)
	if err != nil {
		p.Logger.Error("Failed to encode ready for query response", ErrorField, err)
		return req
	}

	signals, err := v1.NewList([]any{
		sdkAct.Terminate().ToMap(),
		sdkAct.Log(ErrorLevel, DetectionMessage, fields).ToMap(),
	})
	if err != nil {
		p.Logger.Error("Failed to create signals", ErrorField, err)
		return req
	}

	// Create a response to send back to the client.
	req.Fields[sdkAct.Signals] = v1.NewListValue(signals)
	req.Fields[ResponseField] = v1.NewBytesValue(response)
	return req
}
