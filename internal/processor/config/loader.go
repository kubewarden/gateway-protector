package config

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// LoadFile reads, parses, and validates the config file at path, then
// compiles it into a Snapshot.  A nil logger defaults to [slog.Default].
func LoadFile(path string, logger *slog.Logger) (*Snapshot, error) {
	if logger == nil {
		logger = slog.Default()
	}

	cfg, _, err := loadAndHash(path)
	if err != nil {
		return nil, err
	}

	return Compile(cfg, logger)
}

// Watcher watches a config file for changes via inotify (through
// fsnotify) and recompiles it on change, keeping the previously compiled
// Snapshot in place if a reload fails. This mirrors the platform's fail-safe
// principle: a bad reload must never silently disable protection or crash
// the data plane - the processor keeps running whatever the last valid
// configuration was until the problem is fixed (see docs/processor.md).
//
// Watcher watches the file's parent directory rather than the file itself.
// This is what makes it work with Kubernetes ConfigMap mounts: kubelet
// updates a mounted ConfigMap by writing the new content under a new
// "..data_<ts>" directory and atomically repointing the "..data" symlink at
// it, then repointing the file itself to "..data/<file>". A watch on the
// file's inode would never see that swap; a watch on the directory does.
type Watcher struct {
	path     string
	fileName string
	dir      string
	logger   *slog.Logger
	fsWatch  *fsnotify.Watcher
	lastHash [32]byte
}

// NewWatcher creates a Watcher for the config file at path, and starts
// watching its parent directory for changes. Call LoadInitial to get the
// first Snapshot, then Start to begin reacting to filesystem events. Callers
// must call Close when done, whether or not Start was ever called.
//
// A nil logger defaults to [slog.Default].
func NewWatcher(path string, logger *slog.Logger) (*Watcher, error) {
	if logger == nil {
		logger = slog.Default()
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve config file path %q: %w", path, err)
	}
	dir := filepath.Dir(absPath)

	fsWatch, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create filesystem watcher: %w", err)
	}

	if err := fsWatch.Add(dir); err != nil {
		_ = fsWatch.Close()
		return nil, fmt.Errorf("failed to watch config directory %q: %w", dir, err)
	}

	return &Watcher{
		path:     absPath,
		fileName: filepath.Base(absPath),
		dir:      dir,
		logger:   logger,
		fsWatch:  fsWatch,
	}, nil
}

// Close stops watching the filesystem and releases the underlying inotify
// resources.
func (w *Watcher) Close() error {
	if err := w.fsWatch.Close(); err != nil {
		return fmt.Errorf("failed to close filesystem watcher: %w", err)
	}
	return nil
}

// LoadInitial loads, validates, and compiles the config file, remembering
// its content hash so the first filesystem event that isn't an actual
// content change doesn't trigger a needless recompile.
func (w *Watcher) LoadInitial() (*Snapshot, error) {
	cfg, hash, err := loadAndHash(w.path)
	if err != nil {
		return nil, err
	}

	snapshot, err := Compile(cfg, w.logger)
	if err != nil {
		return nil, err
	}

	w.lastHash = hash

	return snapshot, nil
}

// Start reacts to filesystem events on the config file's directory until
// ctx is done or the watcher is closed, calling onChange with a newly
// compiled Snapshot whenever the file's content actually changes.
// Parse/validate/compile errors are logged and otherwise ignored: the
// previously loaded Snapshot (and thus the engines already serving traffic)
// is left untouched.
func (w *Watcher) Start(ctx context.Context, onChange func(*Snapshot)) {
	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-w.fsWatch.Events:
			if !ok {
				return
			}
			if w.isRelevant(event) {
				w.reloadIfChanged(ctx, onChange)
			}
		case err, ok := <-w.fsWatch.Errors:
			if !ok {
				return
			}
			w.logger.ErrorContext(ctx, "Filesystem watcher error", slog.Any("error", err))
		}
	}
}

// isRelevant reports whether event might indicate that the config file's
// content changed. It matches both direct writes to the file and the
// "..data" symlink swap Kubernetes uses to update ConfigMap mounts, and
// ignores everything else in the watched directory.
func (w *Watcher) isRelevant(event fsnotify.Event) bool {
	if !event.Has(fsnotify.Create | fsnotify.Write | fsnotify.Rename | fsnotify.Chmod) {
		return false
	}

	name := filepath.Base(event.Name)
	return name == w.fileName || name == "..data"
}

func (w *Watcher) reloadIfChanged(ctx context.Context, onChange func(*Snapshot)) {
	cfg, hash, err := loadAndHash(w.path)
	if err != nil {
		w.logger.ErrorContext(ctx, "Failed to reload processor config, keeping previous config", slog.Any("error", err))
		return
	}

	if hash == w.lastHash {
		return
	}

	snapshot, err := Compile(cfg, w.logger)
	if err != nil {
		w.logger.ErrorContext(ctx, "Failed to compile reloaded processor config, keeping previous config", slog.Any("error", err))
		return
	}

	w.lastHash = hash
	w.logger.InfoContext(ctx, "Reloaded processor config", slog.String("path", w.path))
	onChange(snapshot)
}

// loadAndHash reads, parses, and validates the config file at path,
// returning the parsed Config alongside a content hash so callers can detect
// no-op reloads without recompiling.
func loadAndHash(path string) (*Config, [32]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("failed to read config file %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return nil, [32]byte{}, fmt.Errorf("failed to parse config file %q: %w", path, err)
	}

	if err := Validate(&cfg); err != nil {
		return nil, [32]byte{}, fmt.Errorf("invalid config file %q: %w", path, err)
	}

	return &cfg, sha256.Sum256(content), nil
}
