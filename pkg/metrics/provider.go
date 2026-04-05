package metrics

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	promexporter "go.opentelemetry.io/otel/exporters/prometheus"
	otlpmetrichttp "go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

// ProviderConfig holds options for building the MeterProvider.
type ProviderConfig struct {
	// PrometheusRegisterer is the prometheus registry to register with.
	// Use prometheus.DefaultRegisterer in production.
	PrometheusRegisterer prometheus.Registerer
}

// NewMeterProvider constructs an sdkmetric.MeterProvider with:
//   - A Prometheus bridge exporter registered on cfg.PrometheusRegisterer
//   - An optional OTLP HTTP push exporter if OTEL_EXPORTER_OTLP_ENDPOINT is set
//
// Returns the provider and a shutdown function.
func NewMeterProvider(ctx context.Context, cfg ProviderConfig) (*sdkmetric.MeterProvider, func(context.Context) error, error) {
	var opts []sdkmetric.Option

	// Always install Prometheus bridge exporter.
	promOpts := []promexporter.Option{}
	if cfg.PrometheusRegisterer != nil {
		promOpts = append(promOpts, promexporter.WithRegisterer(cfg.PrometheusRegisterer))
	}
	promExp, err := promexporter.New(promOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("creating prometheus exporter: %w", err)
	}
	opts = append(opts, sdkmetric.WithReader(promExp))

	// Optional OTLP HTTP push exporter.
	var otlpExp *otlpmetrichttp.Exporter
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" {
		otlpExp, err = otlpmetrichttp.New(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("creating otlp metric exporter: %w", err)
		}
		opts = append(opts, sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(otlpExp, sdkmetric.WithInterval(10*time.Second)),
		))
	}

	provider := sdkmetric.NewMeterProvider(opts...)

	shutdown := func(ctx context.Context) error {
		err := provider.Shutdown(ctx)
		if otlpExp != nil {
			if e2 := otlpExp.Shutdown(ctx); e2 != nil && err == nil {
				err = e2
			}
		}
		return err
	}

	return provider, shutdown, nil
}
