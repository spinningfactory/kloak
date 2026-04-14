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

// Setup initializes a zap logger and configures controller-runtime to use it.
//
// Environment variables:
//   - KLOAK_LOG_DEV=true: use development config (console output, colors)
//   - KLOAK_LOG_LEVEL: override log level (debug, info, warn, error)
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
		var level zapcore.Level
		if err := level.UnmarshalText([]byte(lvl)); err == nil {
			cfg.Level = zap.NewAtomicLevelAt(level)
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
