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
	"syscall"

	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	"github.com/kubewarden/gateway-protector/internal/processor"
	"github.com/kubewarden/gateway-protector/internal/processor/config"
)

func main() {
	os.Exit(run())
}

// Config holds the processor's command-line configuration.
type Config struct {
	GRPCBindAddress  string
	ConfigPath       string
	LogLevel         string
	EnableReflection bool
}

// parseFlags binds and parses the processor's command-line flags into a
// Config.
func parseFlags() Config {
	var cfg Config

	flag.StringVar(&cfg.GRPCBindAddress, "grpc-bind-address", ":9000", "The address the ext_proc gRPC service binds to.")
	flag.StringVar(&cfg.ConfigPath, "config", "/etc/gateway-protector/processor/config.yaml",
		"Path to the processor's data-plane config file (engines + host/path routing table).")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level: debug, info, warn, or error.")
	flag.BoolVar(&cfg.EnableReflection, "grpc-reflection", false, "Enable gRPC server reflection (useful for local debugging).")
	flag.Parse()

	return cfg
}

// run contains all of main's logic so deferred cleanups always execute,
// regardless of which exit path is taken; only main() calls os.Exit.
func run() int {
	cfg := parseFlags()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: parseLogLevel(cfg.LogLevel)}))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	watcher, err := config.NewWatcher(cfg.ConfigPath, logger)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to set up processor config watcher", slog.String("path", cfg.ConfigPath), slog.Any("error", err))
		return 1
	}
	defer watcher.Close()

	initial, err := watcher.LoadInitial()
	if err != nil {
		logger.ErrorContext(ctx, "Failed to load initial processor config", slog.String("path", cfg.ConfigPath), slog.Any("error", err))
		return 1
	}

	proc := processor.New(initial, logger)

	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.GRPCBindAddress)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to bind gRPC listener", slog.String("address", cfg.GRPCBindAddress), slog.Any("error", err))
		return 1
	}
	defer lis.Close()

	grpcServer := grpc.NewServer()
	envoy_service_ext_proc_v3.RegisterExternalProcessorServer(grpcServer, proc)

	healthServer := health.NewServer()
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
	grpc_health_v1.RegisterHealthServer(grpcServer, healthServer)

	if cfg.EnableReflection {
		reflection.Register(grpcServer)
	}

	go watcher.Start(ctx, proc.SetSnapshot)

	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		logger.InfoContext(ctx, "Shutting down processor...")
		healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
		grpcServer.GracefulStop()
		cancel()
	}()

	logger.InfoContext(ctx, "Processor ready", slog.String("grpc-bind-address", cfg.GRPCBindAddress), slog.String("config", cfg.ConfigPath))
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
