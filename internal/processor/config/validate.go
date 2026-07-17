package config

import (
	"errors"
	"fmt"
	"strings"
)

// Validate checks a parsed Config for internal consistency: every
// routes[].waf.engineKey must reference an entry in directives, every
// directives entry must be non-empty, and every route must have a host and
// pathPrefix.
func Validate(cfg *Config) error {
	if len(cfg.Directives) == 0 {
		return errors.New("directives: must define at least one engine")
	}

	for key, directives := range cfg.Directives {
		if strings.TrimSpace(key) == "" {
			return errors.New("directives: engine key must not be empty")
		}
		if strings.TrimSpace(directives) == "" {
			return fmt.Errorf("directives[%s]: must not be empty", key)
		}
	}

	for i, route := range cfg.Routes {
		if strings.TrimSpace(route.Host) == "" {
			return fmt.Errorf("routes[%d]: host must not be empty", i)
		}
		if route.PathPrefix == "" {
			return fmt.Errorf("routes[%d]: pathPrefix must not be empty", i)
		}
		if !strings.HasPrefix(route.PathPrefix, "/") {
			return fmt.Errorf("routes[%d]: pathPrefix %q must start with '/'", i, route.PathPrefix)
		}
		if route.WAF != nil {
			if _, ok := cfg.Directives[route.WAF.EngineKey]; !ok {
				return fmt.Errorf("routes[%d]: waf.engineKey %q has no matching entry in directives", i, route.WAF.EngineKey)
			}
		}
	}

	return nil
}
