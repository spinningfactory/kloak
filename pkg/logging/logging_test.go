package logging

import (
	"reflect"
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
	// Each case asserts both an enabled boundary (the lowest level the logger
	// should accept) and a disabled boundary (the level just below that should
	// be filtered). Trace is split out because it sits below Debug.
	cases := []struct {
		env             string
		dev             string // KLOAK_LOG_DEV value
		enabledAt       zapcore.Level
		disabledBelow   zapcore.Level // any level strictly below this must be off
		hasDisabledEdge bool
	}{
		// Production mode (KLOAK_LOG_DEV unset / "false")
		{env: "trace", dev: "", enabledAt: TraceLevel /* nothing below trace to test */},
		{env: "debug", dev: "", enabledAt: zapcore.DebugLevel, disabledBelow: TraceLevel, hasDisabledEdge: true},
		{env: "info", dev: "", enabledAt: zapcore.InfoLevel, disabledBelow: zapcore.DebugLevel, hasDisabledEdge: true},
		{env: "warn", dev: "", enabledAt: zapcore.WarnLevel, disabledBelow: zapcore.InfoLevel, hasDisabledEdge: true},
		{env: "error", dev: "", enabledAt: zapcore.ErrorLevel, disabledBelow: zapcore.WarnLevel, hasDisabledEdge: true},
		// Garbage value: UnmarshalText fails, Setup keeps config's default (Info for production).
		{env: "garbage", dev: "", enabledAt: zapcore.InfoLevel, disabledBelow: zapcore.DebugLevel, hasDisabledEdge: true},

		// Development mode interactions: KLOAK_LOG_DEV=true switches the base
		// config but the level override still applies on top.
		{env: "trace", dev: "true", enabledAt: TraceLevel},
		{env: "info", dev: "true", enabledAt: zapcore.InfoLevel, disabledBelow: zapcore.DebugLevel, hasDisabledEdge: true},
		{env: "error", dev: "true", enabledAt: zapcore.ErrorLevel, disabledBelow: zapcore.WarnLevel, hasDisabledEdge: true},
		// Dev mode with no level override defaults to Debug (development config default).
		{env: "", dev: "true", enabledAt: zapcore.DebugLevel, disabledBelow: TraceLevel, hasDisabledEdge: true},
	}
	for _, tc := range cases {
		name := tc.env + "/dev=" + tc.dev
		t.Run(name, func(t *testing.T) {
			t.Setenv("KLOAK_LOG_DEV", tc.dev)
			t.Setenv("KLOAK_LOG_LEVEL", tc.env)

			got := Setup()
			core := got.Desugar().Core()
			if !core.Enabled(tc.enabledAt) {
				t.Errorf("expected level %s to be enabled (env=%q dev=%q)", tc.enabledAt, tc.env, tc.dev)
			}
			if tc.hasDisabledEdge && core.Enabled(tc.disabledBelow) {
				t.Errorf("expected level %s to be disabled (env=%q dev=%q)", tc.disabledBelow, tc.env, tc.dev)
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
		want []zap.Field
	}{
		// sweetenFields returns make([]zap.Field, 0, n/2) — a non-nil, length-0
		// slice — even for empty/odd inputs, so use []zap.Field{} (not nil).
		{"empty", nil, []zap.Field{}},
		{"even pair", []interface{}{"k1", "v1"}, []zap.Field{zap.Any("k1", "v1")}},
		{"two pairs",
			[]interface{}{"k1", 1, "k2", 2},
			[]zap.Field{zap.Any("k1", 1), zap.Any("k2", 2)}},
		// Trailing odd element is dropped by the i+=2 bound.
		{"odd dangling element",
			[]interface{}{"k1", "v1", "dangling"},
			[]zap.Field{zap.Any("k1", "v1")}},
		{"single element", []interface{}{"x"}, []zap.Field{}},
		// Non-string keys silently become "" — the type assertion fails and the
		// zero value is used. The value still propagates correctly.
		{"non-string key becomes empty string",
			[]interface{}{42, "v"},
			[]zap.Field{zap.Any("", "v")}},
		// Mixed value types — proves the int / string / interface paths in
		// zap.Field encoding are all preserved.
		{"mixed types",
			[]interface{}{"int_key", 7, "str_key", "s", "iface_key", []byte{1, 2}},
			[]zap.Field{
				zap.Any("int_key", 7),
				zap.Any("str_key", "s"),
				zap.Any("iface_key", []byte{1, 2}),
			}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := sweetenFields(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got  %#v\nwant %#v", got, tc.want)
			}
		})
	}
}
