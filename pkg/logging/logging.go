// Package logging provides a centralized zap logger setup for the kloak project.
// It creates a production or development zap logger based on environment variables
// and bridges it to controller-runtime via zapr.
package logging

import (
	"os"
	"strings"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	ctrl "sigs.k8s.io/controller-runtime"
)

// TraceLevel is a custom log level below Debug for very verbose output
// (per-secret sync, BPF debug counters, etc.).
// Enabled by KLOAK_LOG_LEVEL=trace.
const TraceLevel = zapcore.DebugLevel - 1

// Setup initializes a zap logger and configures controller-runtime to use it.
//
// Environment variables:
//   - KLOAK_LOG_DEV=true: use development config (console output, colors)
//   - KLOAK_LOG_LEVEL: override log level (trace, debug, info, warn, error)
//
// Returns a *zap.SugaredLogger for use throughout the application.
func Setup() *zap.SugaredLogger {
	var cfg zap.Config

	if strings.EqualFold(os.Getenv("KLOAK_LOG_DEV"), "true") {
		cfg = zap.NewDevelopmentConfig()
		cfg.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	} else {
		cfg = zap.NewProductionConfig()
		cfg.EncoderConfig.TimeKey = "ts"
		cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	}

	// Allow level override via environment variable.
	if lvl := os.Getenv("KLOAK_LOG_LEVEL"); lvl != "" {
		if strings.EqualFold(lvl, "trace") {
			cfg.Level = zap.NewAtomicLevelAt(TraceLevel)
		} else {
			var level zapcore.Level
			if err := level.UnmarshalText([]byte(lvl)); err == nil {
				cfg.Level = zap.NewAtomicLevelAt(level)
			}
		}
	}

	zapLogger, err := cfg.Build()
	if err != nil {
		// Fallback to a no-op logger if build fails (should never happen).
		zapLogger = zap.NewNop()
	}

	// Bridge to controller-runtime so that its internal logging uses zap.
	ctrl.SetLogger(zapr.NewLogger(zapLogger))

	return zapLogger.Sugar()
}

// Tracew logs at trace level (below debug). Use for very verbose output
// like per-secret sync details, BPF debug counters, and per-map-entry operations.
func Tracew(log *zap.SugaredLogger, msg string, keysAndValues ...interface{}) {
	if ce := log.Desugar().Check(TraceLevel, msg); ce != nil {
		ce.Write(sweetenFields(keysAndValues)...)
	}
}

// sweetenFields converts key-value pairs to zap.Fields.
func sweetenFields(keysAndValues []interface{}) []zap.Field {
	fields := make([]zap.Field, 0, len(keysAndValues)/2)
	for i := 0; i < len(keysAndValues)-1; i += 2 {
		key, _ := keysAndValues[i].(string)
		fields = append(fields, zap.Any(key, keysAndValues[i+1]))
	}
	return fields
}
