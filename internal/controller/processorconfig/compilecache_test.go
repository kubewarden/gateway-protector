package processorconfig

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// countingCompiler is a DryCompiler that records how many times it was
// actually invoked per engine key, and returns a fixed error for a given
// key when told to fail.
type countingCompiler struct {
	calls map[string]int
	fail  map[string]error
}

func newCountingCompiler() *countingCompiler {
	return &countingCompiler{calls: make(map[string]int), fail: make(map[string]error)}
}

func (c *countingCompiler) compile(engineKey, _ string) error {
	c.calls[engineKey]++

	return c.fail[engineKey]
}

func TestCompileCacheMemoizesSuccess(t *testing.T) {
	fake := newCountingCompiler()
	cache := NewCompileCache(fake.compile)

	require.NoError(t, cache.Compile("a", "directives-a"))
	require.NoError(t, cache.Compile("a", "directives-a"))
	require.NoError(t, cache.Compile("a", "directives-a"))

	assert.Equal(t, 1, fake.calls["a"], "the wrapped compiler should only run once for a repeated key")
}

func TestCompileCacheMemoizesFailure(t *testing.T) {
	fake := newCountingCompiler()
	fake.fail["broken"] = errors.New("boom")
	cache := NewCompileCache(fake.compile)

	err1 := cache.Compile("broken", "bad-directives")
	err2 := cache.Compile("broken", "bad-directives")

	require.Error(t, err1)
	require.Error(t, err2)
	assert.Equal(t, err1, err2)
	assert.Equal(t, 1, fake.calls["broken"], "a memoized failure must not be recompiled")
}

func TestCompileCacheDistinguishesKeys(t *testing.T) {
	fake := newCountingCompiler()
	cache := NewCompileCache(fake.compile)

	require.NoError(t, cache.Compile("a", "directives-a"))
	require.NoError(t, cache.Compile("b", "directives-b"))

	assert.Equal(t, 1, fake.calls["a"])
	assert.Equal(t, 1, fake.calls["b"])
}

func TestCompileCacheSweepEvictsUnseenKeys(t *testing.T) {
	fake := newCountingCompiler()
	cache := NewCompileCache(fake.compile)

	require.NoError(t, cache.Compile("a", "directives-a"))
	require.NoError(t, cache.Compile("b", "directives-b"))
	cache.Sweep()

	// Both were compiled during the cycle this Sweep closed, so both survive it.
	assert.Contains(t, cache.results, "a")
	assert.Contains(t, cache.results, "b")

	// Only "a" is part of this cycle: "b" should be evicted by Sweep.
	require.NoError(t, cache.Compile("a", "directives-a"))
	cache.Sweep()

	assert.Contains(t, cache.results, "a")
	assert.NotContains(t, cache.results, "b", "\"b\" was not compiled this cycle and must be evicted")

	require.NoError(t, cache.Compile("b", "directives-b"))

	assert.Equal(t, 1, fake.calls["a"], "\"a\" was seen every cycle, so it should never recompile")
	assert.Equal(t, 2, fake.calls["b"], "\"b\" was evicted after being unseen for a cycle, so it recompiles once more")
}

func TestCompileCacheSweepKeepsSeenKeysAcrossMultipleCycles(t *testing.T) {
	fake := newCountingCompiler()
	cache := NewCompileCache(fake.compile)

	for range 3 {
		require.NoError(t, cache.Compile("a", "directives-a"))
		cache.Sweep()
	}

	assert.Equal(t, 1, fake.calls["a"], "a key compiled every cycle should only ever compile once")
	assert.Contains(t, cache.results, "a", "\"a\" was seen every cycle and must still be cached")
	assert.Len(t, cache.results, 1, "no other key was ever compiled, so none should be cached")
}
