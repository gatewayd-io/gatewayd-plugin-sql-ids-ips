package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	sdkAct "github.com/gatewayd-io/gatewayd-plugin-sdk/act"
	v1 "github.com/gatewayd-io/gatewayd-plugin-sdk/plugin/v1"
	"github.com/hashicorp/go-hclog"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_isSQLi(t *testing.T) {
	p := &Plugin{
		EnableLibinjection: true,
		Logger:             hclog.NewNullLogger(),
	}
	// This is a false positive, since the query is not an SQL injection.
	assert.True(t, p.isSQLi("SELECT * FROM users WHERE id = 1"))
	// This is an SQL injection.
	assert.True(t, p.isSQLi("SELECT * FROM users WHERE id = 1 OR 1=1"))
}

func Test_isSQLiDisabled(t *testing.T) {
	p := &Plugin{
		EnableLibinjection: false,
		Logger:             hclog.NewNullLogger(),
	}
	// This is an SQL injection, but the libinjection is disabled.
	assert.False(t, p.isSQLi("SELECT * FROM users WHERE id = 1 OR 1=1"))
}

func Test_errorResponse(t *testing.T) {
	p := &Plugin{
		Logger: hclog.NewNullLogger(),
	}

	query := pgproto3.Query{String: "SELECT * FROM users WHERE id = 1 OR 1=1"}
	queryBytes, err := query.Encode(nil)
	require.NoError(t, err)

	req := map[string]any{
		"request": queryBytes,
	}
	reqJSON, err := v1.NewStruct(req)
	require.NoError(t, err)
	assert.NotNil(t, reqJSON)

	resp := p.prepareResponse(
		reqJSON,
		map[string]any{
			"score":    0.9999,
			"detector": "deep_learning_model",
		},
	)
	// We are modifying the pointer to the object, so they should be the same.
	assert.Equal(t, reqJSON, resp)
	assert.Len(t, resp.GetFields(), 3)
	assert.Contains(t, resp.GetFields(), "request")
	assert.Contains(t, resp.GetFields(), "response")
	assert.Contains(t, resp.GetFields(), sdkAct.Signals)
	// 2 signals: Terminate and Log.
	assert.Len(t, resp.Fields[sdkAct.Signals].GetListValue().AsSlice(), 2)
}

func Test_emptyResponse(t *testing.T) {
	p := &Plugin{
		Logger:       hclog.NewNullLogger(),
		ResponseType: "empty",
	}

	query := pgproto3.Query{String: "SELECT * FROM users WHERE id = 1 OR 1=1"}
	queryBytes, err := query.Encode(nil)
	require.NoError(t, err)

	req := map[string]any{
		"request": queryBytes,
	}
	reqJSON, err := v1.NewStruct(req)
	require.NoError(t, err)
	assert.NotNil(t, reqJSON)

	resp := p.prepareResponse(
		reqJSON,
		map[string]any{
			"score":    0.9999,
			"detector": "deep_learning_model",
		},
	)
	assert.Equal(t, reqJSON, resp)
	assert.Len(t, resp.GetFields(), 3)
	assert.Contains(t, resp.GetFields(), "request")
	assert.Contains(t, resp.GetFields(), "response")
	assert.Contains(t, resp.GetFields(), sdkAct.Signals)
	assert.Len(t, resp.Fields[sdkAct.Signals].GetListValue().AsSlice(), 2)
}

func Test_GetPluginConfig(t *testing.T) {
	p := &Plugin{
		Logger: hclog.NewNullLogger(),
	}

	result, err := p.GetPluginConfig(context.Background(), nil)
	require.NoError(t, err)
	assert.NotNil(t, result)
	assert.Contains(t, result.GetFields(), "id")
	assert.Contains(t, result.GetFields(), "hooks")
	assert.Contains(t, result.GetFields(), "config")
}

func Test_OnTrafficFromClient(t *testing.T) {
	p := &Plugin{
		Logger: hclog.NewNullLogger(),
	}

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case PredictPath:
				w.WriteHeader(http.StatusOK)
				w.Header().Set("Content-Type", "application/json")
				// This is the output of the deep learning model.
				resp := map[string][][]float32{"outputs": {{0.999909341}}}
				data, _ := json.Marshal(resp)
				_, err := w.Write(data)
				require.NoError(t, err)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}),
	)
	defer server.Close()

	p.PredictionAPIAddress = server.URL

	query := pgproto3.Query{String: "SELECT * FROM users WHERE id = 1 OR 1=1"}
	queryBytes, err := query.Encode(nil)
	require.NoError(t, err)

	req := map[string]any{
		"request": queryBytes,
	}
	reqJSON, err := v1.NewStruct(req)
	require.NoError(t, err)
	assert.NotNil(t, reqJSON)

	resp, err := p.OnTrafficFromClient(context.Background(), reqJSON)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Len(t, resp.GetFields(), 4)
	assert.Contains(t, resp.GetFields(), "request")
	assert.Contains(t, resp.GetFields(), "query")
	assert.Contains(t, resp.GetFields(), "response")
	assert.Contains(t, resp.GetFields(), sdkAct.Signals)
	// 2 signals: Terminate and Log.
	assert.Len(t, resp.Fields[sdkAct.Signals].GetListValue().AsSlice(), 2)
}

func Test_OnTrafficFromClientFailedTokenization(t *testing.T) {
	plugins := []*Plugin{
		{
			Logger: hclog.NewNullLogger(),
			// If libinjection is enabled, the response should contain the "response" field,
			// and the "signals" field, which means the plugin will terminate the request.
			EnableLibinjection: true,
		},
		{
			Logger: hclog.NewNullLogger(),
			// If libinjection is disabled, the response should not contain the "response" field,
			// and the "signals" field, which means the plugin will not terminate the request.
			EnableLibinjection: false,
		},
	}

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case PredictPath:
				w.WriteHeader(http.StatusInternalServerError)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}),
	)
	defer server.Close()

	for i := range plugins {
		plugins[i].PredictionAPIAddress = server.URL

		query := pgproto3.Query{String: "SELECT * FROM users WHERE id = 1 OR 1=1"}
		queryBytes, err := query.Encode(nil)
		require.NoError(t, err)

		req := map[string]any{
			"request": queryBytes,
		}
		reqJSON, err := v1.NewStruct(req)
		require.NoError(t, err)
		assert.NotNil(t, reqJSON)

		resp, err := plugins[i].OnTrafficFromClient(context.Background(), reqJSON)
		require.NoError(t, err)
		assert.NotNil(t, resp)
		if plugins[i].EnableLibinjection {
			assert.Len(t, resp.GetFields(), 4)
			assert.Contains(t, resp.GetFields(), "request")
			assert.Contains(t, resp.GetFields(), "query")
			assert.Contains(t, resp.GetFields(), "response")
			assert.Contains(t, resp.GetFields(), sdkAct.Signals)
			// 2 signals: Terminate and Log.
			assert.Len(t, resp.Fields[sdkAct.Signals].GetListValue().AsSlice(), 2)
		} else {
			assert.Len(t, resp.GetFields(), 2)
			assert.Contains(t, resp.GetFields(), "request")
			assert.Contains(t, resp.GetFields(), "query")
			assert.NotContains(t, resp.GetFields(), "response")
			assert.NotContains(t, resp.GetFields(), sdkAct.Signals)
		}
	}
}

func Test_OnTrafficFromClientBelowThreshold(t *testing.T) {
	p := &Plugin{
		Logger:    hclog.NewNullLogger(),
		Threshold: 0.8,
	}

	server := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case PredictPath:
				w.WriteHeader(http.StatusOK)
				w.Header().Set("Content-Type", "application/json")
				resp := map[string]any{"confidence": 0.1}
				data, _ := json.Marshal(resp)
				_, err := w.Write(data)
				require.NoError(t, err)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}),
	)
	defer server.Close()

	p.PredictionAPIAddress = server.URL

	query := pgproto3.Query{String: "SELECT name FROM products WHERE id = 42"}
	queryBytes, err := query.Encode(nil)
	require.NoError(t, err)

	req := map[string]any{
		"request": queryBytes,
	}
	reqJSON, err := v1.NewStruct(req)
	require.NoError(t, err)

	resp, err := p.OnTrafficFromClient(context.Background(), reqJSON)
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotContains(t, resp.GetFields(), "response")
	assert.NotContains(t, resp.GetFields(), sdkAct.Signals)
}

func Test_OnTrafficFromClientEmptyQuery(t *testing.T) {
	p := &Plugin{
		Logger: hclog.NewNullLogger(),
	}

	req := map[string]any{
		"request": []byte{},
	}
	reqJSON, err := v1.NewStruct(req)
	require.NoError(t, err)

	resp, err := p.OnTrafficFromClient(context.Background(), reqJSON)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotContains(t, resp.GetFields(), "response")
	assert.NotContains(t, resp.GetFields(), sdkAct.Signals)
}
