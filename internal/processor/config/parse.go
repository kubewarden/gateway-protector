package config

import (
	"encoding/json"
	"fmt"
)

// parseConfig parses and validates content (the JSON encoding of Config -
// see GRPCPublisher.Publish for how the controller produces it) into a
// Config, ready for Compile. Shared by Subscriber, which receives content
// over the config stream.
func parseConfig(content []byte) (*Config, error) {
	var cfg Config
	if err := json.Unmarshal(content, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	if err := Validate(&cfg); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}
