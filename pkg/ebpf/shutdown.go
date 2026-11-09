package ebpf

// ShutdownMode says what a controller leaves of the eBPF data plane when it
// stops (TLSUprobeManager.Shutdown, spinningfactory/kloak#107).
type ShutdownMode int

const (
	// ShutdownDetach detaches every program and removes the pins, but for
	// the virtual IP state (the hosts' fake IPs, which hold no secret): the
	// next controller loads and attaches everything again, and until it
	// has, the pods' TLS writes carry their placeholders.
	ShutdownDetach ShutdownMode = iota
	// ShutdownKeep leaves the pinned programs attached and rewriting, for
	// the next controller to adopt: a restart, a rollout or an upgrade.
	ShutdownKeep
	// ShutdownUninstall detaches everything and removes the whole pin root:
	// kloak is being uninstalled.
	ShutdownUninstall
)

func (m ShutdownMode) String() string {
	switch m {
	case ShutdownDetach:
		return "detach"
	case ShutdownKeep:
		return "keep"
	case ShutdownUninstall:
		return "uninstall"
	default:
		return "unknown"
	}
}
