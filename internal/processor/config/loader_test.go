package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const validConfigYAML = `
directives:
  a: "SecRuleEngine On"
routes:
  - host: example.com
    pathPrefix: /
    waf:
      engineKey: a
`

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validConfigYAML), 0o600))

	snapshot, err := LoadFile(path, nil)
	require.NoError(t, err)

	_, matched := snapshot.Match("example.com", "/")
	require.True(t, matched, "expected a route match from the loaded config")
}

func TestLoadFileErrors(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name       string
		file       string
		content    string
		createFile bool
	}{
		{
			name: "missing file",
			file: "does-not-exist.yaml",
		},
		{
			name:       "invalid yaml",
			file:       "invalid.yaml",
			content:    "not: valid: yaml: at: all:",
			createFile: true,
		},
		{
			name:       "invalid semantics",
			file:       "invalid-semantics.yaml",
			content:    "directives: {}\n",
			createFile: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(dir, tt.file)
			if tt.createFile {
				require.NoError(t, os.WriteFile(path, []byte(tt.content), 0o600))
			}

			_, err := LoadFile(path, nil)
			require.Error(t, err)
		})
	}
}

// newTestWatcher creates a Watcher for path and registers its Close for test
// cleanup.
func newTestWatcher(t *testing.T, path string) *Watcher {
	t.Helper()

	watcher, err := NewWatcher(path, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = watcher.Close() })

	return watcher
}

func TestWatcherReloadsOnChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validConfigYAML), 0o600))

	watcher := newTestWatcher(t, path)
	initial, err := watcher.LoadInitial()
	require.NoError(t, err)
	_, matched := initial.Match("example.com", "/")
	require.True(t, matched, "expected initial snapshot to match example.com")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	reloaded := make(chan *Snapshot, 1)
	go watcher.Start(ctx, func(s *Snapshot) {
		select {
		case reloaded <- s:
		default:
		}
	})

	updatedYAML := `
directives:
  a: "SecRuleEngine On"
routes:
  - host: updated.example.com
    pathPrefix: /
    waf:
      engineKey: a
`
	require.NoError(t, os.WriteFile(path, []byte(updatedYAML), 0o600))

	select {
	case snapshot := <-reloaded:
		_, reloadedMatched := snapshot.Match("updated.example.com", "/")
		require.True(t, reloadedMatched, "expected reloaded snapshot to match updated.example.com")
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for the watcher to reload the config")
	}
}

// TestWatcherReloadsOnAtomicRename simulates how Kubernetes updates a
// ConfigMap volume mount: the new content is written to a different path in
// the same directory, then atomically renamed over the watched file. A
// watch on the file's inode would miss this; Watcher watches the directory
// instead specifically to handle it (see the Watcher doc comment).
func TestWatcherReloadsOnAtomicRename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validConfigYAML), 0o600))

	watcher := newTestWatcher(t, path)
	_, err := watcher.LoadInitial()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	reloaded := make(chan *Snapshot, 1)
	go watcher.Start(ctx, func(s *Snapshot) {
		select {
		case reloaded <- s:
		default:
		}
	})

	updatedYAML := `
directives:
  a: "SecRuleEngine On"
routes:
  - host: renamed.example.com
    pathPrefix: /
    waf:
      engineKey: a
`
	tmpPath := filepath.Join(dir, "config.yaml.tmp")
	require.NoError(t, os.WriteFile(tmpPath, []byte(updatedYAML), 0o600))
	require.NoError(t, os.Rename(tmpPath, path))

	select {
	case snapshot := <-reloaded:
		_, matched := snapshot.Match("renamed.example.com", "/")
		require.True(t, matched, "expected reloaded snapshot to match renamed.example.com")
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for the watcher to reload the atomically-renamed config")
	}
}

func TestWatcherKeepsPreviousSnapshotOnInvalidReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(validConfigYAML), 0o600))

	watcher := newTestWatcher(t, path)
	_, err := watcher.LoadInitial()
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	called := make(chan struct{}, 1)
	go watcher.Start(ctx, func(*Snapshot) {
		select {
		case called <- struct{}{}:
		default:
		}
	})

	time.Sleep(20 * time.Millisecond)
	require.NoError(t, os.WriteFile(path, []byte("not: valid: yaml: at: all:"), 0o600))

	select {
	case <-called:
		t.Fatal("onChange should not be called when the reloaded config is invalid")
	case <-ctx.Done():
		// Expected: the watcher logged the error and kept the previous config.
	}
}
