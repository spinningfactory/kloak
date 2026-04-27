package main

import (
	"os"
	"runtime/coverage"

	"go.uber.org/zap"
)

// flushCoverageCounters writes covcounters to GOCOVERDIR before main returns.
// Without this, the e2e CI consistently captured covmeta but never
// covcounters — Go's automatic at-exit flush for -cover builds is racy on
// SIGTERM under kubelet-managed grace periods. WriteCountersDir is a no-op
// when the binary was built without -cover, so it's safe in production
// images that don't pass GOCOVERDIR.
func flushCoverageCounters(log *zap.SugaredLogger) {
	dir := os.Getenv("GOCOVERDIR")
	if dir == "" {
		return
	}
	if err := coverage.WriteCountersDir(dir); err != nil {
		log.Warnw("failed to flush coverage counters", "dir", dir, "error", err)
		return
	}
	log.Infow("flushed coverage counters", "dir", dir)
}
