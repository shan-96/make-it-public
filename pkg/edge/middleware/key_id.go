package middleware

import (
	"context"
	"net/http"
	"strings"
)

// UpstreamHostHeader is the header name injected by Caddy containing the TLS server name (SNI)
// from the upstream connection. When a CDN like Cloudflare proxies a request via CNAME,
// the Host header contains the custom domain, but the TLS SNI contains the CNAME target
// (the tunnel subdomain). Caddy captures the SNI and injects it as this header.
const UpstreamHostHeader = "X-Upstream-Host"

type keyIDKeyType struct{}

// ParseKeyID extracts the tunnel key ID from the request by resolving the effective host.
// It first checks the X-Upstream-Host header (injected by Caddy from TLS SNI) for CNAME proxy support,
// then falls back to the Host header for direct subdomain access.
// Requests with no valid host matching the domain postfix or missing subdomains receive a 404 response.
// Accepts domainPostfix as a string specifying the desired domain suffix.
// Returns a middleware handler function that attaches the subdomain to the request context and processes the next handler.
func ParseKeyID(domainPostfix string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host := resolveHost(r, domainPostfix)
			if host == "" {
				http.NotFound(w, r)
				return
			}

			keyID := extractKeyIDFromHost(host)
			if keyID == "" {
				http.NotFound(w, r)
				return
			}

			ctx := r.Context()
			ctx = context.WithValue(ctx, keyIDKeyType{}, keyID)
			r = r.WithContext(ctx)

			next.ServeHTTP(w, r)
		})
	}
}

// GetKeyID retrieves the key ID from the request's context if available.
// It returns the key ID as a string, or an empty string if not found or the value is not a string.
func GetKeyID(r *http.Request) string {
	if keyID, ok := r.Context().Value(keyIDKeyType{}).(string); ok {
		return keyID
	}

	return ""
}

// resolveHost determines the effective host for key ID extraction.
// It checks the X-Upstream-Host header first (injected by Caddy from TLS SNI),
// which is the authoritative signal when requests arrive via CDN CNAME proxies.
// Falls back to the standard Host header for direct subdomain access.
// Returns the matching host (without port) or an empty string if neither source matches.
func resolveHost(r *http.Request, domainPostfix string) string {
	// Priority 1: X-Upstream-Host header (CNAME proxy via Caddy TLS SNI).
	// When a CDN like Cloudflare proxies a CNAME request, the Host header contains
	// the custom domain (e.g., app.example.com), but Caddy injects the TLS SNI
	// (the CNAME target, e.g., mykey.make-it-public.dev) as X-Upstream-Host.
	// This header is trusted because Caddy strips any client-supplied value before injecting its own.
	if upstreamHost := r.Header.Get(UpstreamHostHeader); upstreamHost != "" {
		host := strings.Split(upstreamHost, ":")[0]
		if matchesDomain(host, domainPostfix) {
			return host
		}
	}

	// Priority 2: Direct Host header (normal subdomain access).
	host := strings.Split(r.Host, ":")[0]
	if matchesDomain(host, domainPostfix) {
		return host
	}

	return ""
}

// matchesDomain reports whether host is equal to domain or is a subdomain of it.
// It enforces DNS label boundaries, so "evil-example.com" does not match "example.com".
// domainPostfix is the bare domain name without a leading dot (e.g. "make-it-public.dev").
func matchesDomain(host, domainPostfix string) bool {
	return host == domainPostfix || strings.HasSuffix(host, "."+domainPostfix)
}

// extractKeyIDFromHost extracts the subdomain (key ID) from a fully qualified host string.
// It assumes the host follows the subdomain.domain.tld format.
// Returns the subdomain as a string or an empty string if no subdomain exists.
func extractKeyIDFromHost(host string) string {
	if host != "" {
		// Strip port if present
		h := strings.Split(host, ":")[0]

		parts := strings.Split(h, ".")
		if len(parts) > 2 {
			// Extract subdomain (assuming subdomain.domain.tld format)
			return parts[0]
		}
	}

	return ""
}
