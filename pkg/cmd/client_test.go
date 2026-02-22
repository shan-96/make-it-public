package cmd

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRunClientCommand(t *testing.T) {
	testToken := "dGVzdDp0ZXN0"                // #nosec G101 -- base64("test:test"), old-format web token for tests
	tcpToken := "dGVzdGtleS10OnRlc3RzZWNyZXQ=" // #nosec G101 -- base64("testkey-t:testsecret"), TCP token for tests
	webToken := "dGVzdGtleS13OnRlc3RzZWNyZXQ=" // #nosec G101 -- base64("testkey-w:testsecret"), web token for tests

	tests := []struct {
		name    string
		wantErr string
		args    args
	}{
		{
			name: "Invalid log level",
			args: args{
				Token:    testToken,
				Server:   "test-server",
				Expose:   "test-dest",
				NoTLS:    false,
				Insecure: false,
			},
			wantErr: "failed to init logger: slog: level string \"\": unknown name",
		},
		{
			name: "invalid token",
			args: args{
				Token:    "invalid-token",
				Server:   "test-server",
				Expose:   "test-dest",
				NoTLS:    false,
				Insecure: false,
				LogLevel: "info",
			},
			wantErr: "invalid token: illegal base64 data at input byte 7",
		},
		{
			name: "valid token",
			args: args{
				Token:    testToken,
				Server:   "test-server",
				Expose:   "test-dest",
				NoTLS:    false,
				Insecure: false,
				LogLevel: "info",
			},
			wantErr: "failed to split host and port: address test-server: missing port in address",
		},
		{
			name: "local dummy server with invalid headers",
			args: args{
				Token:       testToken,
				Server:      "test-server:8080",
				LocalServer: true,
				NoTLS:       false,
				Insecure:    false,
				LogLevel:    "info",
				Status:      200,
				Body:        "test",
				Headers:     []string{"invalid-header-format"},
			},
			wantErr: "failed to create local server: invalid header format: invalid-header-format (expected 'Name:Value')",
		},
		{
			name: "local dummy server with valid headers",
			args: args{
				Token:       testToken,
				Server:      "test-server:8080",
				LocalServer: true,
				NoTLS:       false,
				Insecure:    false,
				LogLevel:    "info",
				Status:      200,
				Body:        "test",
				Headers:     []string{"X-Custom-Header:value"},
			},
			wantErr: "lookup test-server",
		},
		{
			name: "websocket echo server",
			args: args{
				Token:    testToken,
				Server:   "test-server:8080",
				EchoWS:   true,
				NoTLS:    false,
				Insecure: false,
				LogLevel: "info",
			},
			wantErr: "lookup test-server",
		},
		{
			name: "both dummy and echo-ws flags",
			args: args{
				Token:       testToken,
				Server:      "test-server:8080",
				LocalServer: true,
				EchoWS:      true,
				NoTLS:       false,
				Insecure:    false,
				LogLevel:    "info",
			},
			wantErr: "cannot use both --dummy and --echo-ws flags",
		},
		{
			name: "TCP token with --dummy flag is rejected",
			args: args{
				Token:       tcpToken,
				Server:      "test-server:8080",
				LocalServer: true,
				NoTLS:       false,
				Insecure:    false,
				LogLevel:    "info",
			},
			wantErr: "--dummy and --echo-ws are only supported with web tokens",
		},
		{
			name: "TCP token with --echo-ws flag is rejected",
			args: args{
				Token:    tcpToken,
				Server:   "test-server:8080",
				EchoWS:   true,
				NoTLS:    false,
				Insecure: false,
				LogLevel: "info",
			},
			wantErr: "--dummy and --echo-ws are only supported with web tokens",
		},
		{
			name: "web token with --dummy flag is allowed past TCP check",
			args: args{
				Token:       webToken,
				Server:      "test-server:8080",
				LocalServer: true,
				NoTLS:       false,
				Insecure:    false,
				LogLevel:    "info",
				Status:      200,
			},
			// Fails at DNS lookup, not at the TCP token check — confirms web tokens pass validation
			wantErr: "lookup test-server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()

			// Act
			err := RunClientCommand(ctx, &tt.args)

			// Assert
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
