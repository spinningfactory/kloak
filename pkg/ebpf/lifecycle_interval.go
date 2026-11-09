package ebpf

import "time"

// LifecycleSweepInterval is how often the controller runs RunLifecycleSweep.
const LifecycleSweepInterval = 30 * time.Second
