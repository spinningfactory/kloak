package lds

import (
	"fmt"

	cluster "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	core "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	listener "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	route "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcm "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	sniv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/cert_mappers/sni/v3"
	on_demand_secretv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/cert_selectors/on_demand_secret/v3"
	tls "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"

	// Filter configs
	dfp_common "github.com/envoyproxy/go-control-plane/envoy/extensions/common/dynamic_forward_proxy/v3"
	dfp "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	extproc "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/ext_proc/v3"
	router "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	tls_inspector "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// MakeListener creates the main listener for the xDS server.
// Uses on-demand certificate selection with SNI as the SDS secret name.
func MakeListener(port int) (*listener.Listener, error) {
	// 1. TLS Inspector Listener Filter to extract SNI
	tlsInspector := &listener.ListenerFilter{
		Name: "envoy.filters.listener.tls_inspector",
		ConfigType: &listener.ListenerFilter_TypedConfig{
			TypedConfig: mustMarshalAny(&tls_inspector.TlsInspector{}),
		},
	}

	// 2. HTTP Connection Manager
	manager := &hcm.HttpConnectionManager{
		CodecType:  hcm.HttpConnectionManager_AUTO,
		StatPrefix: "ingress_http",
		RouteSpecifier: &hcm.HttpConnectionManager_RouteConfig{
			RouteConfig: &route.RouteConfiguration{
				Name: "local_route",
				VirtualHosts: []*route.VirtualHost{{
					Name:    "local_service",
					Domains: []string{"*"},
					Routes: []*route.Route{{
						Match: &route.RouteMatch{
							PathSpecifier: &route.RouteMatch_Prefix{Prefix: "/"},
						},
						Action: &route.Route_Route{
							Route: &route.RouteAction{
								ClusterSpecifier: &route.RouteAction_Cluster{
									Cluster: "dynamic_forward_proxy_cluster",
								},
								HostRewriteSpecifier: &route.RouteAction_AutoHostRewrite{
									AutoHostRewrite: wrapperspb.Bool(true),
								},
							},
						},
					}},
				}},
			},
		},
		HttpFilters: []*hcm.HttpFilter{
			{
				Name: "envoy.filters.http.ext_proc",
				ConfigType: &hcm.HttpFilter_TypedConfig{
					TypedConfig: mustMarshalAny(
						&extproc.ExternalProcessor{
							GrpcService: &core.GrpcService{
								TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
									EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
										ClusterName: "ext_proc_server",
									},
								},
								Timeout: &durationpb.Duration{Seconds: 1},
							},
							ProcessingMode: &extproc.ProcessingMode{
								RequestHeaderMode:  extproc.ProcessingMode_SEND,
								ResponseHeaderMode: extproc.ProcessingMode_SKIP,
							},
						},
					),
				},
			},
			{
				Name: "envoy.filters.http.dynamic_forward_proxy",
				ConfigType: &hcm.HttpFilter_TypedConfig{
					TypedConfig: mustMarshalAny(
						&dfp.FilterConfig{
							ImplementationSpecifier: &dfp.FilterConfig_DnsCacheConfig{
								DnsCacheConfig: &dfp_common.DnsCacheConfig{
									Name:            "dynamic_forward_proxy_cache_config",
									DnsLookupFamily: cluster.Cluster_V4_ONLY,
								},
							},
						},
					),
				},
			},
			{
				Name: "envoy.filters.http.router",
				ConfigType: &hcm.HttpFilter_TypedConfig{
					TypedConfig: mustMarshalAny(&router.Router{}),
				},
			},
		},
	}
	pbst, err := anypb.New(manager)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal HCM: %w", err)
	}

	// 3. Create on-demand certificate selector config
	// This uses SNI as the SDS secret name
	onDemandSelector, err := makeOnDemandCertSelector()
	if err != nil {
		return nil, fmt.Errorf("failed to create on-demand cert selector: %w", err)
	}

	// 4. Single filter chain with on-demand certificate selection
	filterChain := &listener.FilterChain{
		Name: "tls_intercept",
		Filters: []*listener.Filter{{
			Name: "envoy.filters.network.http_connection_manager",
			ConfigType: &listener.Filter_TypedConfig{
				TypedConfig: pbst,
			},
		}},
		TransportSocket: &core.TransportSocket{
			Name: "envoy.transport_sockets.tls",
			ConfigType: &core.TransportSocket_TypedConfig{
				TypedConfig: mustMarshalAny(&tls.DownstreamTlsContext{
					CommonTlsContext: &tls.CommonTlsContext{
						// Use custom certificate selector for on-demand SDS
						CustomTlsCertificateSelector: onDemandSelector,
					},
					// Disable session resumption for on-demand certs
					DisableStatefulSessionResumption: true,
					SessionTicketKeysType: &tls.DownstreamTlsContext_DisableStatelessSessionResumption{
						DisableStatelessSessionResumption: true,
					},
				}),
			},
		},
	}

	return &listener.Listener{
		Name: "tls_intercept_listener",
		Address: &core.Address{
			Address: &core.Address_SocketAddress{
				SocketAddress: &core.SocketAddress{
					Address: "0.0.0.0",
					PortSpecifier: &core.SocketAddress_PortValue{
						PortValue: uint32(port),
					},
				},
			},
		},
		ListenerFilters: []*listener.ListenerFilter{tlsInspector},
		FilterChains:    []*listener.FilterChain{filterChain},
	}, nil
}

// makeOnDemandCertSelector creates the custom TLS certificate selector config
// that uses SNI as the SDS secret name for on-demand certificate fetching.
func makeOnDemandCertSelector() (*core.TypedExtensionConfig, error) {
	// 1. Create ConfigSource using native Go types to ensure correctness
	cs := &core.ConfigSource{
		ResourceApiVersion: core.ApiVersion_V3,
		ConfigSourceSpecifier: &core.ConfigSource_ApiConfigSource{
			ApiConfigSource: &core.ApiConfigSource{
				ApiType:             core.ApiConfigSource_DELTA_GRPC,
				TransportApiVersion: core.ApiVersion_V3,
				GrpcServices: []*core.GrpcService{{
					TargetSpecifier: &core.GrpcService_EnvoyGrpc_{
						EnvoyGrpc: &core.GrpcService_EnvoyGrpc{
							ClusterName: "sds_server",
						},
					},
				}},
			},
		},
	}

	a, err := anypb.New(&sniv3.SNI{DefaultValue: "default-bounder-sni"})
	onDemandConfig := &on_demand_secretv3.Config{
		ConfigSource: cs,
		CertificateMapper: &core.TypedExtensionConfig{
			Name:        "sni-cert-mapper",
			TypedConfig: a,
		},
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create on_demand_config struct: %w", err)
	}

	// Wrap in Any with the on-demand secret type URL
	configAny, err := anypb.New(onDemandConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal on_demand_config: %w", err)
	}
	//// Override the type URL since we're using Struct as a placeholder
	//configAny.TypeUrl = "type.googleapis.com/envoy.extensions.transport_sockets.tls.cert_selectors.on_demand_secret.v3.Config"

	return &core.TypedExtensionConfig{
		Name:        "on-demand",
		TypedConfig: configAny,
	}, nil
}

func mustMarshalAny(m proto.Message) *anypb.Any {
	a, err := anypb.New(m)
	if err != nil {
		panic(err)
	}
	return a
}
