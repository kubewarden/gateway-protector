package config

import "log/slog"

// MetadataNamespace is the ext_proc metadata namespace that carries a
// request's Identity: every AgentgatewayPolicy the controller generates
// asks agentgateway to fill it (see internal/controller's
// wiringMetadataContext), and agentgateway sends it in
// ProcessingRequest.metadata_context.filter_metadata.
const MetadataNamespace = "gateway-protector.kubewarden.io"

// The keys of MetadataNamespace, one per Identity field. Each value must be
// a string; every key must be present, even when its value is empty.
const (
	MetadataKeyGatewayNamespace = "gatewayNamespace"
	MetadataKeyGatewayName      = "gatewayName"
	MetadataKeyListenerName     = "listenerName"
	MetadataKeyRouteKind        = "routeKind"
	MetadataKeyRouteNamespace   = "routeNamespace"
	MetadataKeyRouteName        = "routeName"
	MetadataKeyRouteRule        = "routeRule"
)

// Identity is the Gateway API identity of one request, as agentgateway
// reports it: the Gateway and listener that accepted the request, and the
// route and rule that agentgateway selected for it.
type Identity struct {
	GatewayNamespace string
	GatewayName      string
	ListenerName     string

	// RouteKind is the kind of the selected route, e.g. KindHTTPRoute.
	RouteKind      string
	RouteNamespace string
	RouteName      string

	// RouteRule is the name of the selected rule, or empty when the rule
	// has no name.
	RouteRule string
}

// LogValue implements [slog.LogValuer]. The zero Identity logs as an empty
// group, which slog handlers omit.
func (id Identity) LogValue() slog.Value {
	if id == (Identity{}) {
		return slog.GroupValue()
	}

	return slog.GroupValue(
		slog.String("gateway", id.GatewayNamespace+"/"+id.GatewayName),
		slog.String("listener", id.ListenerName),
		slog.String("route_kind", id.RouteKind),
		slog.String("route", id.RouteNamespace+"/"+id.RouteName),
		slog.String("rule", id.RouteRule),
	)
}

// attachmentPoints returns the attachment points a request with this
// identity can resolve to, most specific first: the same precedence as
// WAFPolicy attachment (see docs/policy-attachment.md).
func (id Identity) attachmentPoints() []AttachmentPoint {
	points := make([]AttachmentPoint, 0, 4)

	if id.RouteKind == KindHTTPRoute {
		if id.RouteRule != "" {
			points = append(points, AttachmentPoint{Kind: KindHTTPRoute, Namespace: id.RouteNamespace, Name: id.RouteName, SectionName: id.RouteRule})
		}

		points = append(points, AttachmentPoint{Kind: KindHTTPRoute, Namespace: id.RouteNamespace, Name: id.RouteName})
	}

	if id.ListenerName != "" {
		points = append(points, AttachmentPoint{Kind: KindGateway, Namespace: id.GatewayNamespace, Name: id.GatewayName, SectionName: id.ListenerName})
	}

	return append(points, AttachmentPoint{Kind: KindGateway, Namespace: id.GatewayNamespace, Name: id.GatewayName})
}
