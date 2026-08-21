// Package containerlog provides a small testcontainers.LogConsumer that
// buffers a container's output in memory, shared by every containerized
// suite under test/ (test/ftw, test/coraza-e2e) that fronts agentgateway
// with a real container and wants its logs available for triage without
// re-running - see OnFailure. It lives under test/internal rather than
// test/ so it can never be imported by production code (Go's internal
// package visibility rule confines it to packages rooted at test/).
package containerlog

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
)

// Collector is a testcontainers.LogConsumer that buffers a container's
// output in memory so it can be dumped into the test log on failure (see
// OnFailure), or inspected directly by a test that needs to assert on
// what a container actually logged.
type Collector struct {
	mu      sync.Mutex
	builder strings.Builder
}

// Accept implements testcontainers.LogConsumer.
func (c *Collector) Accept(log testcontainers.Log) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.builder.Write(log.Content)
}

// String returns everything collected so far.
func (c *Collector) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.builder.String()
}

// OnFailure streams a container's stdout/stderr into the test log when
// (and only when) the test fails, to make triaging remote-CI failures
// possible without re-running.
func OnFailure(t *testing.T, name string) *testcontainers.LogConsumerConfig {
	t.Helper()

	collector := &Collector{}
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("=== %s container logs ===\n%s", name, collector.String())
		}
	})

	return &testcontainers.LogConsumerConfig{
		Opts:      []testcontainers.LogProductionOption{testcontainers.WithLogProductionTimeout(10 * time.Second)},
		Consumers: []testcontainers.LogConsumer{collector},
	}
}
