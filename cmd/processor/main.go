// Command processor runs the Envoy ext_proc gRPC service: a Coraza-based WAF
// engine selected per request by host+path, wired to agentgateway via the
// AgentgatewayPolicy the controller generates.
package main

import (
	"context"
	"flag"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/kubewarden/gateway-protector/internal/certs"
	"github.com/kubewarden/gateway-protector/internal/processor"
	"github.com/kubewarden/gateway-protector/internal/processor/config"
)

func main() {
	os.Exit(run())
}

// Config holds the processor's command-line configuration.
type Config struct {
	GRPCBindAddress     string
	ConfigServerAddress string
	SubscriberID        string
	LogLevel            string
	EnableReflection    bool
	ConfigStreamCertDir string
}

// parseFlags binds and parses the processor's command-line flags into a
// Config.
func parseFlags() Config {
	var cfg Config

	flag.StringVar(&cfg.GRPCBindAddress, "grpc-bind-address", ":9000", "The address the ext_proc gRPC service binds to.")
	flag.StringVar(&cfg.ConfigServerAddress, "config-server-address", "",
		"The controller's config stream gRPC address (host:port) this processor subscribes its data-plane "+
			"config (engines + host/path routing table) from. Required.")
	flag.StringVar(&cfg.SubscriberID, "subscriber-id", "", "Identifies this replica to the controller's config "+
		"stream logs/metrics (e.g. this pod's name). Defaults to the hostname if unset.")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level: debug, info, warn, or error.")
	flag.BoolVar(&cfg.EnableReflection, "grpc-reflection", false, "Enable gRPC server reflection (useful for local debugging).")
	flag.StringVar(&cfg.ConfigStreamCertDir, "config-stream-cert-dir", "",
		"Directory containing this processor's client certificate (tls.crt, tls.key) and the CA bundle "+
			"(ca.crt) used to verify the controller's config stream server certificate. If unset, the config "+
			"stream is dialed in plaintext.")
	flag.Parse()

	if cfg.SubscriberID == "" {
		if hostname, err := os.Hostname(); err == nil {
			cfg.SubscriberID = hostname
		}
	}

	return cfg
}

// run contains all of main's logic so deferred cleanups always execute,
// regardless of which exit path is taken; only main() calls os.Exit.
func run() int {
	cfg := parseFlags()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel(cfg.LogLevel)}))

	if cfg.ConfigServerAddress == "" {
		logger.Error("--config-server-address is required")
		return 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proc := processor.New(nil, logger)

	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.GRPCBindAddress)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to bind gRPC listener", slog.String("address", cfg.GRPCBindAddress), slog.Any("error", err))
		return 1
	}
	defer lis.Close()

	grpcServer := grpc.NewServer()
	envoy_service_ext_proc_v3.RegisterExternalProcessorServer(grpcServer, proc)

	healthServer := health.NewServer()
	// NOT_SERVING until the first config is applied (see onChange below):
	// a processor with no config loaded should not be marked ready, since
	// Process would otherwise fail open (skip the WAF) for every request
	// it receives in the meantime - see internal/processor.Server.
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	if cfg.EnableReflection {
		reflection.Register(grpcServer)
	}

	var readyOnce sync.Once
	onChange := func(snapshot *config.Snapshot) {
		proc.SetSnapshot(snapshot)
		readyOnce.Do(func() {
			logger.InfoContext(ctx, "Received initial config from controller, marking processor ready")
			healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
		})
	}

	subscriber := config.NewSubscriber(cfg.ConfigServerAddress, cfg.SubscriberID, logger, configStreamCreds(cfg.ConfigStreamCertDir))
	go func() {
		if err := subscriber.Run(ctx, onChange); err != nil {
			logger.ErrorContext(ctx, "Config stream subscriber stopped", slog.Any("error", err))
		}
	}()

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		logger.InfoContext(ctx, "Shutting down processor...")
		healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		grpcServer.GracefulStop()
		cancel()
	}()

	logger.InfoContext(ctx, "Processor ready",
		slog.String("grpc-bind-address", cfg.GRPCBindAddress),
		slog.String("config-server-address", cfg.ConfigServerAddress),
		slog.Bool("config-stream-mtls", cfg.ConfigStreamCertDir != ""),
		slog.String("crs-version", config.EmbeddedCRSVersion()))
	if err := grpcServer.Serve(lis); err != nil {
		logger.ErrorContext(ctx, "gRPC server failed", slog.Any("error", err))
		return 1
	}

	return 0
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// configStreamCreds returns the transport credentials the config stream
// Subscriber dials with: mTLS client credentials reloaded from certDir on
// every handshake if certDir is set, or nil (plaintext) otherwise.
func configStreamCreds(certDir string) credentials.TransportCredentials {
	if certDir == "" {
		return nil
	}

	return certs.NewReloadingClientCredentials(certDir)
}
