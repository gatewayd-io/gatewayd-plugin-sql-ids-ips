package plugin

import (
	"context"
	"encoding/base64"

	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	"github.com/hashicorp/go-hclog"
	goplugin "github.com/hashicorp/go-plugin"
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
	// Example req:
	// {
	//     "client": {
	//         "local": "0.0.0.0:15432",
	//         "remote": "127.0.0.1:45612"
	//     },
	//     "error": "",
	//     "query": "eyJUeXBlIjoiUXVlcnkiLCJTdHJpbmciOiJzZWxlY3QgMTsifQ==",
	//     "request": "UQAAAA5zZWxlY3QgMTsA",
	//     "server": {
	//         "local": "127.0.0.1:60386",
	//         "remote": "127.0.0.1:5432"
	//     }
	// }
	p.Logger.Debug("OnTrafficFromClient", "req", req)

	request := req.Fields["request"].GetStringValue()
	if reqBytes, err := base64.StdEncoding.DecodeString(request); err == nil {
		p.Logger.Debug("OnTrafficFromClient", "request", string(reqBytes))
	}

	return req, nil
}
