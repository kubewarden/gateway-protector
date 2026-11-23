package controller

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	configstreamv1 "github.com/kubewarden/gateway-protector/internal/configstream/v1"
	procconfig "github.com/kubewarden/gateway-protector/internal/processor/config"
)

// ConfigPublisher hands the compiled processor configuration to the data
// plane. GRPCPublisher is the only implementation: it feeds ConfigServer,
// which pushes the config over the config stream (see
// proto/configstream/v1) to every connected processor replica.
type ConfigPublisher interface {
	Publish(ctx context.Context, cfg *procconfig.Config) error
}

// GRPCPublisher publishes the processor configuration by handing it to a
// ConfigServer, which pushes it to every currently connected processor
// replica over the config stream and tracks each replica's ConfigAck (see
// ConfigServer's doc comment).
type GRPCPublisher struct {
	Server *ConfigServer
}

var _ ConfigPublisher = &GRPCPublisher{}

// Publish renders cfg as JSON - the same encoding both sides' config
// package already parses/validates/compiles - and hands it to p.Server
// alongside a sha256 hex digest that both sides use as the config's
// version: to detect no-op pushes here, and to correlate a subscriber's
// ConfigAck back to the snapshot it's acking.
//
// That hash is only meaningful if identical logical config always produces
// identical bytes, which depends on two things holding together:
//
//   - cfg itself must be canonical: processorconfig.Build (the only
//     producer of the Config this reconciler publishes) documents its
//     output ordering (Bindings sorted by kind/namespace/name/sectionName)
//     as an invariant precisely so that rebuilding from the same accepted
//     WAFPolicy/WAFRuleSet set - regardless of the
//     arbitrary iteration order the controller-runtime cache's List
//     returns them in - never spuriously produces a "changed" config.
//   - encoding/json's own marshaling must be deterministic, which it is:
//     struct fields are always encoded in declaration order and map keys
//     (Config.Directives here) are always sorted - see encoding/json's
//     Marshal doc comment.
//
// There is deliberately no attempt to canonicalize the JSON bytes
// themselves (e.g. RFC 8785/JCS): that guards against multiple independent
// producers/serializers disagreeing on the same logical value, which
// doesn't apply here - this Publish call is the only place the config is
// ever serialized or hashed; every subscriber only ever echoes the version
// string back in its ConfigAck, it never re-derives it (see
// Subscriber.applySnapshot).
func (p *GRPCPublisher) Publish(_ context.Context, cfg *procconfig.Config) error {
	data, err := json.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal processor config: %w", err)
	}

	version := sha256.Sum256(data)

	p.Server.Publish(&configstreamv1.ConfigSnapshot{
		Version:    hex.EncodeToString(version[:]),
		ConfigJson: data,
	})

	return nil
}
