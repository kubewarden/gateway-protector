package corazae2e

import (
	"strings"
	"sync"

	"github.com/testcontainers/testcontainers-go"
)

// logCollector is a testcontainers.LogConsumer that buffers a container's
// output in memory so it can be dumped into the test log on failure (see
// containerLogsOnFailure).
type logCollector struct {
	mu      sync.Mutex
	builder strings.Builder
}

// Accept implements testcontainers.LogConsumer.
func (c *logCollector) Accept(log testcontainers.Log) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.builder.Write(log.Content)
}

// String returns everything collected so far.
func (c *logCollector) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()

	return c.builder.String()
}
