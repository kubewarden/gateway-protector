package processor

import (
	"errors"
	"fmt"

	envoy_config_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/kubewarden/gateway-protector/internal/processor/config"
)

// identityFromMetadata reads the Identity of a request from the ext_proc
// metadata that every generated AgentgatewayPolicy asks agentgateway to
// send (see config.MetadataNamespace). Every key must be present and hold
// a string. The Gateway and route names must not be empty; the listener
// name, the route kind, and the rule name can be.
//
// An error means agentgateway sent the request without a usable identity,
// for example because a user-written AgentgatewayPolicy sends traffic to
// the processor without the metadata, or because agentgateway failed to
// evaluate one of the expressions. The caller fails the request closed.
func identityFromMetadata(metadata *envoy_config_core_v3.Metadata) (config.Identity, error) {
	namespace, found := metadata.GetFilterMetadata()[config.MetadataNamespace]
	if !found {
		return config.Identity{}, fmt.Errorf("metadata namespace %q is missing", config.MetadataNamespace)
	}

	fields := namespace.GetFields()

	var errs []error

	read := func(key string, required bool) string {
		value, present := fields[key]
		if !present {
			errs = append(errs, fmt.Errorf("key %q is missing", key))
			return ""
		}

		str, ok := value.GetKind().(*structpb.Value_StringValue)
		if !ok {
			errs = append(errs, fmt.Errorf("key %q is not a string", key))
			return ""
		}

		if required && str.StringValue == "" {
			errs = append(errs, fmt.Errorf("key %q is empty", key))
		}

		return str.StringValue
	}

	identity := config.Identity{
		GatewayNamespace: read(config.MetadataKeyGatewayNamespace, true),
		GatewayName:      read(config.MetadataKeyGatewayName, true),
		ListenerName:     read(config.MetadataKeyListenerName, false),
		RouteKind:        read(config.MetadataKeyRouteKind, false),
		RouteNamespace:   read(config.MetadataKeyRouteNamespace, true),
		RouteName:        read(config.MetadataKeyRouteName, true),
		RouteRule:        read(config.MetadataKeyRouteRule, false),
	}

	if err := errors.Join(errs...); err != nil {
		return config.Identity{}, fmt.Errorf("metadata namespace %q: %w", config.MetadataNamespace, err)
	}

	return identity, nil
}
