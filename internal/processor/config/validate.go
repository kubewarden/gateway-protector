package config

import (
	"errors"
	"fmt"
	"strings"
)

// Validate checks a parsed Config for internal consistency: every
// routes[].waf.engineKey must reference an entry in directives, every
// directives entry must be non-empty, and every route must have a valid
// host and pathPrefix.
//
// An empty config (no directives, no routes) is valid: it's the state a
// fresh installation publishes before any WAFPolicy exists anywhere in the
// cluster, and nothing in it references a missing engine, so there is
// nothing to reject.
func Validate(cfg *Config) error {
	for key, directives := range cfg.Directives {
		if strings.TrimSpace(key) == "" {
			return errors.New("directives: engine key must not be empty")
		}
		if strings.TrimSpace(directives) == "" {
			return fmt.Errorf("directives[%s]: must not be empty", key)
		}
	}

	for i, route := range cfg.Routes {
		if err := validateHost(route.Host); err != nil {
			return fmt.Errorf("routes[%d]: %w", i, err)
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

// validateHost checks that host is one of the three forms Snapshot's
// matching supports (see snapshot.go): an exact hostname, a wildcard
// "*.<suffix>" matching any strict subdomain of suffix, or the catch-all
// "*". A bare "*" elsewhere in the string (e.g. "*foo.com", "a.*.com") is
// rejected.
func validateHost(host string) error {
	if strings.TrimSpace(host) == "" {
		return errors.New("host must not be empty")
	}

	if host == "*" {
		return nil
	}

	if strings.HasPrefix(host, "*.") {
		if strings.TrimSpace(host[2:]) == "" {
			return fmt.Errorf("host %q: wildcard suffix must not be empty", host)
		}
		if strings.Contains(host[2:], "*") {
			return fmt.Errorf("host %q: only a single leading wildcard label is supported", host)
		}

		return nil
	}

	if strings.Contains(host, "*") {
		return fmt.Errorf("host %q: '*' is only supported as the whole host or as a leading \"*.\" label", host)
	}

	return nil
}
