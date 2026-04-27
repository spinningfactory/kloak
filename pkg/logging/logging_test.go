package logging

import (
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestSetup_DefaultIsProduction(t *testing.T) {
	t.Setenv("KLOAK_LOG_DEV", "")
	t.Setenv("KLOAK_LOG_LEVEL", "")

	got := Setup()
	if got == nil {
		t.Fatal("Setup() returned nil")
	}
	// Production config defaults to InfoLevel — Debug should be disabled.
	if got.Desugar().Core().Enabled(zapcore.DebugLevel) {
		t.Error("default (production) logger should not be at Debug level")
	}
	if !got.Desugar().Core().Enabled(zapcore.InfoLevel) {
		t.Error("default (production) logger should be at Info level")
	}
}

func TestSetup_DevModeEnablesDebug(t *testing.T) {
	t.Setenv("KLOAK_LOG_DEV", "true")
	t.Setenv("KLOAK_LOG_LEVEL", "")

	got := Setup()
	// Development config defaults to DebugLevel.
	if !got.Desugar().Core().Enabled(zapcore.DebugLevel) {
		t.Error("development logger should be at Debug level")
	}
}

func TestSetup_LevelMatrix(t *testing.T) {
	cases := []struct {
		env        string
		minEnabled zapcore.Level
		debugOff   bool
		traceOn    bool
	}{
		{env: "trace", minEnabled: TraceLevel, traceOn: true},
		{env: "debug", minEnabled: zapcore.DebugLevel},
		{env: "info", minEnabled: zapcore.InfoLevel, debugOff: true},
		{env: "warn", minEnabled: zapcore.WarnLevel, debugOff: true},
		{env: "error", minEnabled: zapcore.ErrorLevel, debugOff: true},
		// Unmarshal failure on an unknown level — Setup keeps the config's default.
		{env: "garbage", minEnabled: zapcore.InfoLevel, debugOff: true},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv("KLOAK_LOG_DEV", "")
			t.Setenv("KLOAK_LOG_LEVEL", tc.env)

			got := Setup()
			core := got.Desugar().Core()
			if !core.Enabled(tc.minEnabled) {
				t.Errorf("expected %s to be enabled at level %s", tc.env, tc.minEnabled)
			}
			if tc.debugOff && core.Enabled(zapcore.DebugLevel) {
				t.Errorf("Debug should be disabled at level %s", tc.env)
			}
			if tc.traceOn && !core.Enabled(TraceLevel) {
				t.Errorf("Trace should be enabled at level %s", tc.env)
			}
		})
	}
}

func TestSetup_LevelIsCaseInsensitive(t *testing.T) {
	t.Setenv("KLOAK_LOG_DEV", "TRUE") // strings.EqualFold path
	t.Setenv("KLOAK_LOG_LEVEL", "TRACE")

	got := Setup()
	if !got.Desugar().Core().Enabled(TraceLevel) {
		t.Error("KLOAK_LOG_LEVEL=TRACE should enable TraceLevel")
	}
}

func TestTracew_EmitsAtTraceLevel(t *testing.T) {
	core, recorded := observer.New(TraceLevel)
	logger := zap.New(core).Sugar()

	Tracew(logger, "hello", "k1", "v1", "k2", 42)

	entries := recorded.All()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Level != TraceLevel {
		t.Errorf("expected TraceLevel, got %v", e.Level)
	}
	if e.Message != "hello" {
		t.Errorf("expected message 'hello', got %q", e.Message)
	}
	fields := e.ContextMap()
	if v, ok := fields["k1"]; !ok || v != "v1" {
		t.Errorf("expected field k1=v1, got %v", fields)
	}
	// zap stores integers as int64 in ContextMap.
	if v, ok := fields["k2"]; !ok || v != int64(42) {
		t.Errorf("expected field k2=42, got %v", fields)
	}
}

func TestTracew_NoOpWhenLevelDisabled(t *testing.T) {
	// Observer at InfoLevel won't accept Trace entries.
	core, recorded := observer.New(zapcore.InfoLevel)
	logger := zap.New(core).Sugar()

	Tracew(logger, "should-not-appear", "k", "v")

	if recorded.Len() != 0 {
		t.Errorf("expected 0 entries when TraceLevel is disabled, got %d", recorded.Len())
	}
}

func TestSweetenFields(t *testing.T) {
	cases := []struct {
		name string
		in   []interface{}
		want int
	}{
		{"empty", nil, 0},
		{"even pair", []interface{}{"k1", "v1"}, 1},
		{"two pairs", []interface{}{"k1", 1, "k2", 2}, 2},
		// Trailing odd element is dropped by the i+=2 bound.
		{"odd dangling element", []interface{}{"k1", "v1", "dangling"}, 1},
		{"single element", []interface{}{"x"}, 0},
		// Non-string keys silently become "".
		{"non-string key tolerated", []interface{}{42, "v"}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sweetenFields(tc.in)
			if len(got) != tc.want {
				t.Errorf("expected %d fields, got %d (%v)", tc.want, len(got), got)
			}
		})
	}
}
