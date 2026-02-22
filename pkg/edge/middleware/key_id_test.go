package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseKeyID(t *testing.T) {
	tests := []struct {
		name          string
		domainPostfix string
		host          string
		upstreamHost  string
		expectedKeyID string
		wantStatus    int
	}{
		{
			name:          "valid host with keyID",
			domainPostfix: ".example.com",
			host:          "keyID.example.com",
			expectedKeyID: "keyID",
			wantStatus:    http.StatusOK,
		},
		{
			name:          "invalid host without domain postfix",
			domainPostfix: ".example.com",
			host:          "keyID.notexample.com",
			expectedKeyID: "",
			wantStatus:    http.StatusNotFound,
		},
		{
			name:          "valid host without keyID",
			domainPostfix: ".example.com",
			host:          "example.com",
			expectedKeyID: "",
			wantStatus:    http.StatusNotFound,
		},
		{
			name:          "empty host",
			domainPostfix: ".example.com",
			host:          "",
			expectedKeyID: "",
			wantStatus:    http.StatusNotFound,
		},
		{
			name:          "CNAME proxy: host does not match but upstream host does",
			domainPostfix: ".example.com",
			host:          "app.custom-domain.com",
			upstreamHost:  "mykey.example.com",
			expectedKeyID: "mykey",
			wantStatus:    http.StatusOK,
		},
		{
			name:          "CNAME proxy: upstream host with port",
			domainPostfix: ".example.com",
			host:          "app.custom-domain.com",
			upstreamHost:  "mykey.example.com:443",
			expectedKeyID: "mykey",
			wantStatus:    http.StatusOK,
		},
		{
			name:          "CNAME proxy: upstream host wrong domain",
			domainPostfix: ".example.com",
			host:          "app.custom-domain.com",
			upstreamHost:  "mykey.otherdomain.com",
			expectedKeyID: "",
			wantStatus:    http.StatusNotFound,
		},
		{
			name:          "CNAME proxy: upstream host has no subdomain",
			domainPostfix: ".example.com",
			host:          "app.custom-domain.com",
			upstreamHost:  "example.com",
			expectedKeyID: "",
			wantStatus:    http.StatusNotFound,
		},
		{
			name:          "direct access: upstream host also set and both match",
			domainPostfix: ".example.com",
			host:          "mykey.example.com",
			upstreamHost:  "mykey.example.com",
			expectedKeyID: "mykey",
			wantStatus:    http.StatusOK,
		},
		{
			name:          "upstream host takes priority over host header",
			domainPostfix: ".example.com",
			host:          "other.example.com",
			upstreamHost:  "mykey.example.com",
			expectedKeyID: "mykey",
			wantStatus:    http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := ParseKeyID(tt.domainPostfix)

			// Create a dummy handler to validate the middleware
			handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				keyID := GetKeyID(r)
				assert.Equal(t, tt.expectedKeyID, keyID)
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.Host = tt.host

			if tt.upstreamHost != "" {
				req.Header.Set(UpstreamHostHeader, tt.upstreamHost)
			}

			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			assert.Equal(t, tt.wantStatus, rec.Result().StatusCode)
		})
	}
}

func TestGetKeyID(t *testing.T) {
	tests := []struct {
		name          string
		contextValues map[interface{}]interface{}
		expectedKeyID string
	}{
		{
			name:          "keyID exists in context",
			contextValues: map[interface{}]interface{}{keyIDKeyType{}: "mockKeyID"},
			expectedKeyID: "mockKeyID",
		},
		{
			name:          "keyID missing in context",
			contextValues: map[interface{}]interface{}{},
			expectedKeyID: "",
		},
		{
			name:          "context value is not a string",
			contextValues: map[interface{}]interface{}{keyIDKeyType{}: 1234},
			expectedKeyID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			for key, value := range tt.contextValues {
				ctx = context.WithValue(ctx, key, value)
			}

			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody).WithContext(ctx)
			actualKeyID := GetKeyID(req)

			assert.Equal(t, tt.expectedKeyID, actualKeyID)
		})
	}
}

func TestResolveHost(t *testing.T) {
	tests := []struct {
		name          string
		host          string
		upstreamHost  string
		domainPostfix string
		expected      string
	}{
		{
			name:          "direct access: host matches domain",
			host:          "mykey.example.com",
			domainPostfix: ".example.com",
			expected:      "mykey.example.com",
		},
		{
			name:          "direct access: host with port",
			host:          "mykey.example.com:8080",
			domainPostfix: ".example.com",
			expected:      "mykey.example.com",
		},
		{
			name:          "direct access: host does not match domain",
			host:          "mykey.other.com",
			domainPostfix: ".example.com",
			expected:      "",
		},
		{
			name:          "CNAME proxy: upstream host matches domain",
			host:          "app.custom-domain.com",
			upstreamHost:  "mykey.example.com",
			domainPostfix: ".example.com",
			expected:      "mykey.example.com",
		},
		{
			name:          "CNAME proxy: upstream host with port",
			host:          "app.custom-domain.com",
			upstreamHost:  "mykey.example.com:443",
			domainPostfix: ".example.com",
			expected:      "mykey.example.com",
		},
		{
			name:          "CNAME proxy: upstream host wrong domain",
			host:          "app.custom-domain.com",
			upstreamHost:  "mykey.otherdomain.com",
			domainPostfix: ".example.com",
			expected:      "",
		},
		{
			name:          "upstream host takes priority over host header",
			host:          "other.example.com",
			upstreamHost:  "mykey.example.com",
			domainPostfix: ".example.com",
			expected:      "mykey.example.com",
		},
		{
			name:          "both headers empty",
			host:          "",
			upstreamHost:  "",
			domainPostfix: ".example.com",
			expected:      "",
		},
		{
			name:          "upstream host empty falls back to host",
			host:          "mykey.example.com",
			upstreamHost:  "",
			domainPostfix: ".example.com",
			expected:      "mykey.example.com",
		},
		{
			name:          "upstream host invalid domain falls back to host",
			host:          "mykey.example.com",
			upstreamHost:  "mykey.invalid.com",
			domainPostfix: ".example.com",
			expected:      "mykey.example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			req.Host = tt.host

			if tt.upstreamHost != "" {
				req.Header.Set(UpstreamHostHeader, tt.upstreamHost)
			}

			actual := resolveHost(req, tt.domainPostfix)
			assert.Equal(t, tt.expected, actual)
		})
	}
}

func TestExtractKeyIDFromHost(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		expected string
	}{
		{
			name:     "valid host with subdomain",
			host:     "keyID.example.com",
			expected: "keyID",
		},
		{
			name:     "host without subdomain",
			host:     "example.com",
			expected: "",
		},
		{
			name:     "empty host",
			host:     "",
			expected: "",
		},
		{
			name:     "host with multiple subdomains",
			host:     "keyID.sub.example.com",
			expected: "keyID",
		},
		{
			name:     "invalid host with multiple dots but no subdomain",
			host:     ".example.com",
			expected: "",
		},
		{
			name:     "host with port",
			host:     "keyID.example.com:8080",
			expected: "keyID",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := extractKeyIDFromHost(tt.host)
			assert.Equal(t, tt.expected, actual)
		})
	}
}
