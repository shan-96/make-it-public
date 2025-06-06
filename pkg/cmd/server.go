package cmd

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ksysoev/make-it-public/pkg/api"
	"github.com/ksysoev/make-it-public/pkg/core"
	"github.com/ksysoev/make-it-public/pkg/edge"
	"github.com/ksysoev/make-it-public/pkg/repo/auth"
	"github.com/ksysoev/make-it-public/pkg/repo/connmng"
	"github.com/ksysoev/make-it-public/pkg/revproxy"
	"golang.org/x/sync/errgroup"
)

// RunServerCommand initializes and starts both reverse proxy and HTTP servers for handling revclient connections.
// It takes ctx of type context.Context for managing the server lifecycle and args of type *args to load configuration.
// It returns an error if the configuration fails to load, servers cannot start, or any runtime error occurs.
func RunServerCommand(ctx context.Context, args *args) error {
	if err := initLogger(args); err != nil {
		return fmt.Errorf("failed to init logger: %w", err)
	}

	cfg, err := loadConfig(args)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	authRepo := auth.New(&cfg.Auth)
	connManager := connmng.New()
	connService := core.New(connManager, authRepo)
	apiServ := api.New(cfg.API, connService)

	revServ, err := revproxy.New(&cfg.RevProxy, connService)
	if err != nil {
		return fmt.Errorf("failed to create reverse proxy server: %w", err)
	}

	httpServ, err := edge.New(cfg.HTTP, connService)
	if err != nil {
		return fmt.Errorf("failed to create http server: %w", err)
	}

	slog.InfoContext(ctx, "server started", "http", cfg.HTTP.Listen, "rev", cfg.RevProxy.Listen, "api", cfg.API.Listen)

	eg, ctx := errgroup.WithContext(ctx)

	eg.Go(func() error { return revServ.Run(ctx) })
	eg.Go(func() error { return httpServ.Run(ctx) })
	eg.Go(func() error { return apiServ.Run(ctx) })

	return eg.Wait()
}
