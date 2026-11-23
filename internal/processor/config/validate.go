package config

import (
	"errors"
	"fmt"
	"strings"
)

// Validate checks a parsed Config for internal consistency: the schema
// version must be SchemaVersion, every directives entry must be non-empty,
// every binding must name a Gateway or HTTPRoute, at most one binding may
// exist per attachment point, and every bindings[].waf.engineKey must
// reference an entry in directives.
//
// A config with no directives and no bindings is valid: it's the state a
// fresh installation publishes before any WAFPolicy exists anywhere in the
// cluster, and nothing in it references a missing engine, so there is
// nothing to reject.
func Validate(cfg *Config) error {
	if cfg.SchemaVersion != SchemaVersion {
		return fmt.Errorf("schemaVersion %d is not supported, this processor supports schemaVersion %d: "+
			"the controller and the processor have incompatible versions", cfg.SchemaVersion, SchemaVersion)
	}

	for key, directives := range cfg.Directives {
		if strings.TrimSpace(key) == "" {
			return errors.New("directives: engine key must not be empty")
		}
		if strings.TrimSpace(directives) == "" {
			return fmt.Errorf("directives[%s]: must not be empty", key)
		}
	}

	seen := make(map[AttachmentPoint]struct{}, len(cfg.Bindings))

	for i, binding := range cfg.Bindings {
		if err := validateBinding(binding, cfg.Directives); err != nil {
			return fmt.Errorf("bindings[%d]: %w", i, err)
		}

		point := binding.AttachmentPoint()
		if _, duplicate := seen[point]; duplicate {
			return fmt.Errorf("bindings[%d]: more than one binding for %s", i, point)
		}
		seen[point] = struct{}{}
	}

	return nil
}

func validateBinding(binding Binding, directives map[string]string) error {
	if binding.Kind != KindGateway && binding.Kind != KindHTTPRoute {
		return fmt.Errorf("kind %q must be %q or %q", binding.Kind, KindGateway, KindHTTPRoute)
	}
	if binding.Namespace == "" {
		return errors.New("namespace must not be empty")
	}
	if binding.Name == "" {
		return errors.New("name must not be empty")
	}
	if binding.WAF != nil {
		if _, ok := directives[binding.WAF.EngineKey]; !ok {
			return fmt.Errorf("waf.engineKey %q has no matching entry in directives", binding.WAF.EngineKey)
		}
	}

	return nil
}
