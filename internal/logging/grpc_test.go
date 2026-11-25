package logging

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/grpclog"
)

func newTestGRPCLogger(level slog.Level) (*GRPCLogger, *bytes.Buffer) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: level})

	return NewGRPCLogger(slog.New(handler)), &buf
}

func decodeRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()

	var records []map[string]any
	for line := range strings.Lines(buf.String()) {
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record), "line is not JSON: %q", line)
		records = append(records, record)
	}

	return records
}

func TestGRPCLoggerLevelsAndMessages(t *testing.T) {
	tests := []struct {
		name      string
		log       func(*GRPCLogger)
		wantLevel string
		wantMsg   string
	}{
		{name: "Info", log: func(l *GRPCLogger) { l.Info("a", "b") }, wantLevel: "DEBUG", wantMsg: "ab"},
		{name: "Infoln", log: func(l *GRPCLogger) { l.Infoln("a", "b") }, wantLevel: "DEBUG", wantMsg: "a b"},
		{name: "Infof", log: func(l *GRPCLogger) { l.Infof("a=%d", 1) }, wantLevel: "DEBUG", wantMsg: "a=1"},
		{name: "Warning", log: func(l *GRPCLogger) { l.Warning("a", "b") }, wantLevel: "WARN", wantMsg: "ab"},
		{name: "Warningln", log: func(l *GRPCLogger) { l.Warningln("a", "b") }, wantLevel: "WARN", wantMsg: "a b"},
		{name: "Warningf", log: func(l *GRPCLogger) { l.Warningf("a=%d", 1) }, wantLevel: "WARN", wantMsg: "a=1"},
		{name: "Error", log: func(l *GRPCLogger) { l.Error("a", "b") }, wantLevel: "ERROR", wantMsg: "ab"},
		{name: "Errorln", log: func(l *GRPCLogger) { l.Errorln("a", "b") }, wantLevel: "ERROR", wantMsg: "a b"},
		{name: "Errorf", log: func(l *GRPCLogger) { l.Errorf("a=%d", 1) }, wantLevel: "ERROR", wantMsg: "a=1"},
		{name: "Fatal", log: func(l *GRPCLogger) { l.Fatal("a", "b") }, wantLevel: "ERROR", wantMsg: "ab"},
		{name: "Fatalln", log: func(l *GRPCLogger) { l.Fatalln("a", "b") }, wantLevel: "ERROR", wantMsg: "a b"},
		{name: "Fatalf", log: func(l *GRPCLogger) { l.Fatalf("a=%d", 1) }, wantLevel: "ERROR", wantMsg: "a=1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, buf := newTestGRPCLogger(slog.LevelDebug)

			tt.log(logger)

			records := decodeRecords(t, buf)
			require.Len(t, records, 1)
			assert.Equal(t, tt.wantLevel, records[0]["level"])
			assert.Equal(t, tt.wantMsg, records[0]["msg"])
			assert.Equal(t, "grpc", records[0]["logger"])
		})
	}
}

func TestGRPCLoggerHidesInfoAtInfoLevel(t *testing.T) {
	logger, buf := newTestGRPCLogger(slog.LevelInfo)

	logger.Info("hidden")
	logger.Infoln("hidden")
	logger.Infof("%s", "hidden")
	logger.Warning("shown")

	records := decodeRecords(t, buf)
	require.Len(t, records, 1)
	assert.Equal(t, "shown", records[0]["msg"])
}

func TestGRPCLoggerV(t *testing.T) {
	logger, _ := newTestGRPCLogger(slog.LevelDebug)

	assert.True(t, logger.V(0))
	assert.False(t, logger.V(1))
	assert.False(t, logger.V(2))
}

// TestGRPCLoggerThroughGRPCLog checks the lines of the component loggers
// that grpc-go uses internally: they reach the logger through Warningln,
// with the component name as the first argument.
func TestGRPCLoggerThroughGRPCLog(t *testing.T) {
	logger, buf := newTestGRPCLogger(slog.LevelInfo)
	grpclog.SetLoggerV2(logger)

	grpclog.Component("core").Warningf("failed to connect to %s", "controller:9002")

	records := decodeRecords(t, buf)
	require.Len(t, records, 1)
	assert.Equal(t, "WARN", records[0]["level"])
	assert.Equal(t, "[core] failed to connect to controller:9002", records[0]["msg"])
	assert.Equal(t, "grpc", records[0]["logger"])
}
