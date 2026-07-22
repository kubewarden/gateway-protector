package processorconfig

// CompileCache memoizes DryCompiler outcomes by engine key. This is sound
// because the key is a content hash of the rendered directives (see
// EngineKey): an identical key always means identical directives, so an
// identical compile outcome (success or the exact same failure) can be
// reused instead of re-running Coraza's (comparatively expensive - tens of
// milliseconds and non-trivial allocations per engine, see
// internal/processor/config's compile benchmarks) compile step on every
// Build, even when nothing relevant actually changed (e.g. an HTTPRoute
// event that doesn't touch any policy's effective configuration).
//
// CompileCache is not safe for concurrent use. It doesn't need to be:
// ProcessorConfigReconciler is a singleton reconciler with the default
// MaxConcurrentReconciles of 1, and its priming run goes through the same
// serialized workqueue as every watch-driven reconcile (see
// processor_config_reconciler.go's SetupWithManager) - two Build calls
// never run concurrently against the same CompileCache.
type CompileCache struct {
	inner   DryCompiler
	results map[string]compileCacheEntry
}

type compileCacheEntry struct {
	err  error
	seen bool
}

// NewCompileCache wraps inner with memoization.
func NewCompileCache(inner DryCompiler) *CompileCache {
	return &CompileCache{
		inner:   inner,
		results: make(map[string]compileCacheEntry),
	}
}

// Compile implements DryCompiler: on the first call for a given engineKey
// (or the first call since it was last evicted by Sweep) it delegates to
// the wrapped DryCompiler and remembers the outcome; every subsequent call
// for the same engineKey returns the remembered outcome without compiling
// again.
func (c *CompileCache) Compile(engineKey, directives string) error {
	if entry, ok := c.results[engineKey]; ok {
		entry.seen = true
		c.results[engineKey] = entry

		return entry.err
	}

	err := c.inner(engineKey, directives)
	c.results[engineKey] = compileCacheEntry{err: err, seen: true}

	return err
}

// Sweep evicts every engine key that wasn't Compile'd since the previous
// Sweep (or since the cache was created), and resets the seen marker on the
// rest. Call it once after each Build so the cache tracks only engines that
// are part of the current world - a policy that stops rendering some
// engine (e.g. deleted, or its directives changed) doesn't keep that stale
// entry - and old cached failures for content nobody references anymore
// don't linger forever.
func (c *CompileCache) Sweep() {
	for key, entry := range c.results {
		if !entry.seen {
			delete(c.results, key)
			continue
		}

		entry.seen = false
		c.results[key] = entry
	}
}
