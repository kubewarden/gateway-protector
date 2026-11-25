// Package logging adapts the loggers of third-party libraries to
// [log/slog], so that a binary writes each log line through one
// [slog.Handler].
package logging

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc/grpclog"
)

// grpcLoggerName is the value of the "logger" attribute of each line that a
// GRPCLogger writes. logr uses the same key for the names of its loggers.
const grpcLoggerName = "grpc"

// GRPCLogger is a [grpclog.LoggerV2] that writes to a [slog.Logger],
// instead of the plain text that the default logger of grpc-go writes to
// stderr.
//
// It maps the gRPC severities to slog levels:
//   - INFO to DEBUG. gRPC uses it for the state changes of channels and
//     connections, and the default logger of grpc-go hides it.
//   - WARNING to WARN.
//   - ERROR and FATAL to ERROR. grpc-go itself exits after a FATAL log.
type GRPCLogger struct {
	logger *slog.Logger
}

var _ grpclog.LoggerV2 = (*GRPCLogger)(nil)

// NewGRPCLogger returns a GRPCLogger that writes to logger, with the
// attribute logger=grpc on each line.
func NewGRPCLogger(logger *slog.Logger) *GRPCLogger {
	return &GRPCLogger{logger: logger.With(slog.String("logger", grpcLoggerName))}
}

func (g *GRPCLogger) Info(args ...any) {
	g.logPrint(slog.LevelDebug, args...)
}

func (g *GRPCLogger) Infoln(args ...any) {
	g.logPrintln(slog.LevelDebug, args...)
}

func (g *GRPCLogger) Infof(format string, args ...any) {
	g.logPrintf(slog.LevelDebug, format, args...)
}

func (g *GRPCLogger) Warning(args ...any) {
	g.logPrint(slog.LevelWarn, args...)
}

func (g *GRPCLogger) Warningln(args ...any) {
	g.logPrintln(slog.LevelWarn, args...)
}

func (g *GRPCLogger) Warningf(format string, args ...any) {
	g.logPrintf(slog.LevelWarn, format, args...)
}

func (g *GRPCLogger) Error(args ...any) {
	g.logPrint(slog.LevelError, args...)
}

func (g *GRPCLogger) Errorln(args ...any) {
	g.logPrintln(slog.LevelError, args...)
}

func (g *GRPCLogger) Errorf(format string, args ...any) {
	g.logPrintf(slog.LevelError, format, args...)
}

func (g *GRPCLogger) Fatal(args ...any) {
	g.logPrint(slog.LevelError, args...)
}

func (g *GRPCLogger) Fatalln(args ...any) {
	g.logPrintln(slog.LevelError, args...)
}

func (g *GRPCLogger) Fatalf(format string, args ...any) {
	g.logPrintf(slog.LevelError, format, args...)
}

// V reports whether the verbosity level l is enabled. Like the default
// logger of grpc-go without GRPC_GO_LOG_VERBOSITY_LEVEL, it enables level 0
// only.
func (g *GRPCLogger) V(l int) bool {
	return l <= 0
}

func (g *GRPCLogger) logPrint(level slog.Level, args ...any) {
	g.log(level, func() string { return fmt.Sprint(args...) })
}

func (g *GRPCLogger) logPrintln(level slog.Level, args ...any) {
	g.log(level, func() string { return strings.TrimSuffix(fmt.Sprintln(args...), "\n") })
}

func (g *GRPCLogger) logPrintf(level slog.Level, format string, args ...any) {
	g.log(level, func() string { return fmt.Sprintf(format, args...) })
}

// log builds the message only if level is enabled: gRPC logs at INFO often,
// and the DEBUG level that INFO maps to is usually disabled.
func (g *GRPCLogger) log(level slog.Level, msg func() string) {
	ctx := context.Background()
	if g.logger.Enabled(ctx, level) {
		g.logger.Log(ctx, level, msg())
	}
}
