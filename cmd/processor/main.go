// Command processor runs the Envoy ext_proc gRPC service: a Coraza-based WAF
// engine selected per request by the Gateway, listener, route, and rule that
// agentgateway reports, wired to agentgateway via the AgentgatewayPolicy the
// controller generates.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"

	envoy_service_ext_proc_v3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/go-logr/logr"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/grpclog"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/certwatcher"
	ctrllog "sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/kubewarden/gateway-protector/internal/certs"
	"github.com/kubewarden/gateway-protector/internal/logging"
	"github.com/kubewarden/gateway-protector/internal/processor"
	"github.com/kubewarden/gateway-protector/internal/processor/config"
)

func main() {
	os.Exit(run())
}

// Config holds the processor's command-line configuration.
type Config struct {
	GRPCBindAddress     string
	HealthBindAddress   string
	ConfigServerAddress string
	SubscriberID        string
	LogLevel            string
	EnableReflection    bool
	ConfigStreamCertDir string
	ExtProcCertDir      string
	WAFMatchedRulesLog  string
}

// parseFlags binds and parses the processor's command-line flags into a
// Config.
func parseFlags() Config {
	var cfg Config

	flag.StringVar(&cfg.GRPCBindAddress, "grpc-bind-address", ":9000", "The address the ext_proc gRPC service binds to.")
	flag.StringVar(&cfg.HealthBindAddress, "health-bind-address", ":9001",
		"The address the plaintext gRPC health service binds to. Kept separate from --grpc-bind-address "+
			"because Kubernetes' native gRPC probes can't present a client certificate, and --ext-proc-cert-dir "+
			"requires one on --grpc-bind-address.")
	flag.StringVar(&cfg.ConfigServerAddress, "config-server-address", "",
		"The controller's config stream gRPC address (host:port) this processor subscribes its data-plane "+
			"config (engines + their bindings to Gateways and HTTPRoutes) from. Required.")
	flag.StringVar(&cfg.SubscriberID, "subscriber-id", "", "Identifies this replica to the controller's config "+
		"stream logs/metrics (e.g. this pod's name). Defaults to the hostname if unset.")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level: debug, info, warn, or error.")
	flag.BoolVar(&cfg.EnableReflection, "grpc-reflection", false, "Enable gRPC server reflection (useful for local debugging).")
	flag.StringVar(&cfg.ConfigStreamCertDir, "config-stream-cert-dir", "",
		"Directory containing this processor's client certificate (tls.crt, tls.key) and the CA bundle "+
			"(ca.crt) used to verify the controller's config stream server certificate. If unset, the config "+
			"stream is dialed in plaintext.")
	flag.StringVar(&cfg.ExtProcCertDir, "ext-proc-cert-dir", "",
		"Directory containing this processor's ext_proc server certificate (tls.crt, tls.key) and the CA "+
			"bundle (ca.crt) used to verify agentgateway's client certificate. If unset, the ext_proc service "+
			"is served in plaintext.")
	flag.StringVar(&cfg.WAFMatchedRulesLog, "waf-matched-rules-log", "",
		"Path to additionally append every matched WAF rule to, one per line, in ModSecurity's own log "+
			"format (ErrorLog) rather than this processor's structured log. For tooling that expects that "+
			"format, e.g. go-ftw or ModSecurity-log-aware SIEM/blocking tools. The file is "+
			"created if missing and appended to if it exists. If unset (the default), no such file is written; "+
			"matched rules are still logged in the processor's normal structured log either way.")
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
	redirectLibraryLogs(logger)

	if cfg.ConfigServerAddress == "" {
		logger.Error("--config-server-address is required")
		return 1
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	proc := processor.New(nil, logger)

	extProcCreds, watcher, err := extProcServerCreds(cfg.ExtProcCertDir)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to build ext_proc server TLS configuration", slog.Any("error", err))
		return 1
	}
	if watcher != nil {
		go func() {
			if err := watcher.Start(ctx); err != nil {
				logger.ErrorContext(ctx, "ext_proc certificate watcher stopped", slog.Any("error", err))
			}
		}()
	}

	lis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.GRPCBindAddress)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to bind gRPC listener", slog.String("address", cfg.GRPCBindAddress), slog.Any("error", err))
		return 1
	}
	defer lis.Close()

	var grpcOpts []grpc.ServerOption
	if extProcCreds != nil {
		grpcOpts = append(grpcOpts, grpc.Creds(extProcCreds))
	}
	grpcServer := grpc.NewServer(grpcOpts...)
	envoy_service_ext_proc_v3.RegisterExternalProcessorServer(grpcServer, proc)

	if cfg.EnableReflection {
		reflection.Register(grpcServer)
	}

	// The gRPC health service is served from its own plaintext listener
	// (see --health-bind-address): Kubernetes' native gRPC probes can't
	// present a client certificate, so they can't reach a health service
	// registered on the (potentially mTLS) ext_proc listener above.
	healthLis, err := (&net.ListenConfig{}).Listen(ctx, "tcp", cfg.HealthBindAddress)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to bind health gRPC listener", slog.String("address", cfg.HealthBindAddress), slog.Any("error", err))
		return 1
	}
	defer healthLis.Close()

	healthServer := health.NewServer()
	// NOT_SERVING until the first config is applied (see onChange below):
	// a processor with no config loaded should not be marked ready, since
	// Process would otherwise fail open (skip the WAF) for every request
	// it receives in the meantime - see internal/processor.Server.
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_NOT_SERVING)
	healthGRPCServer := grpc.NewServer()
	grpc_health_v1.RegisterHealthServer(healthGRPCServer, healthServer)
	go func() {
		if err := healthGRPCServer.Serve(healthLis); err != nil {
			logger.ErrorContext(ctx, "health gRPC server failed", slog.Any("error", err))
		}
	}()

	var readyOnce sync.Once
	onChange := func(snapshot *config.Snapshot) {
		proc.SetSnapshot(snapshot)
		readyOnce.Do(func() {
			logger.InfoContext(ctx, "Received initial config from controller, marking processor ready")
			healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
		})
	}

	subscriber := config.NewSubscriber(cfg.ConfigServerAddress, cfg.SubscriberID, logger, configStreamCreds(cfg.ConfigStreamCertDir))

	if cfg.WAFMatchedRulesLog != "" {
		matchedRulesFile, err := os.OpenFile(cfg.WAFMatchedRulesLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			logger.ErrorContext(ctx, "Failed to open --waf-matched-rules-log", slog.String("path", cfg.WAFMatchedRulesLog), slog.Any("error", err))
			return 1
		}
		defer matchedRulesFile.Close()

		subscriber.SetCompileOptions(config.WithMatchedRuleWriter(matchedRulesFile))
	}

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
		healthGRPCServer.GracefulStop()
		grpcServer.GracefulStop()
		cancel()
	}()

	logger.InfoContext(ctx, "Processor ready",
		slog.String("grpc-bind-address", cfg.GRPCBindAddress),
		slog.String("health-bind-address", cfg.HealthBindAddress),
		slog.String("config-server-address", cfg.ConfigServerAddress),
		slog.Bool("config-stream-mtls", cfg.ConfigStreamCertDir != ""),
		slog.Bool("ext-proc-mtls", cfg.ExtProcCertDir != ""),
		slog.Bool("waf-matched-rules-log", cfg.WAFMatchedRulesLog != ""),
		slog.String("crs-version", config.EmbeddedCRSVersion()))
	if err := grpcServer.Serve(lis); err != nil {
		logger.ErrorContext(ctx, "gRPC server failed", slog.Any("error", err))
		return 1
	}

	return 0
}

// redirectLibraryLogs makes the libraries that the processor uses write
// their logs to logger, so that each line of the processor log is JSON.
// Otherwise they write plain text to stderr: controller-runtime, which the
// ext_proc certificate watcher uses, prints a warning with a stack trace 30
// seconds after the start because its logger is not set, and grpc-go and
// klog have their own text loggers. It must run before these libraries log
// anything: the klog and grpc-go setters are not safe for concurrent use.
func redirectLibraryLogs(logger *slog.Logger) {
	ctrllog.SetLogger(logr.FromSlogHandler(logger.Handler()))
	klog.SetSlogLogger(logger)
	grpclog.SetLoggerV2(logging.NewGRPCLogger(logger))
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

// extProcServerCreds returns the server transport credentials the ext_proc
// gRPC service is served with - requiring and verifying agentgateway's
// client certificate, with the server's own certificate hot-reloaded from
// certDir by the returned watcher - or (nil, nil, nil) for plaintext if
// certDir is unset. The caller must run watcher.Start(ctx) (e.g. in a
// goroutine) for hot-reload to take effect; see certs.ServerTLSConfig.
func extProcServerCreds(certDir string) (credentials.TransportCredentials, *certwatcher.CertWatcher, error) {
	if certDir == "" {
		return nil, nil, nil
	}

	tlsConfig, watcher, err := certs.ServerTLSConfig(certDir)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build ext_proc server TLS config from %q: %w", certDir, err)
	}

	return credentials.NewTLS(tlsConfig), watcher, nil
}
