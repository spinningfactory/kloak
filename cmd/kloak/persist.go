package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
	appsv1 "k8s.io/api/apps/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/spinningfactory/kloak/pkg/controller"
	"github.com/spinningfactory/kloak/pkg/ebpf"
)

// The eBPF data plane outlives the controller (spinningfactory/kloak#107):
// these decide when it is kept, and keep two controllers off one node's
// pins.

// DefaultNodeLock is the node lock's path: a hostPath directory, so that
// the controllers that follow each other on a node share it.
const DefaultNodeLock = "/run/kloak/lock"

// shutdownLookupTimeout bounds the shutdown's look at the DaemonSet: past
// it, the controller can't tell whether kloak stays, and detaches.
const shutdownLookupTimeout = 3 * time.Second

// lockNode takes the node lock at path, an flock: one controller at a time
// may touch the node's pinned eBPF objects. A controller that starts while
// the previous one still shuts down (its pod force-deleted, or a rollout
// that surges) waits for it to exit. The lock goes with the process; the
// returned file holds it.
func lockNode(ctx context.Context, path string, log *zap.SugaredLogger) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("creating the node lock's directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the node lock: %w", err)
	}
	t := time.NewTicker(time.Second)
	defer t.Stop()
	waited := time.Now()
	logged := time.Time{}
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			if !logged.IsZero() {
				log.Infow("took the node lock", "path", path, "waited", time.Since(waited).Round(time.Second).String())
			}
			return f, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			_ = f.Close()
			return nil, fmt.Errorf("taking the node lock %s: %w", path, err)
		}
		if logged.IsZero() || time.Since(logged) > 10*time.Second {
			log.Infow("another kloak controller holds the node lock: waiting for it to exit", "path", path)
			logged = time.Now()
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("waiting for the node lock %s: %w", path, ctx.Err())
		case <-t.C:
		}
	}
}

// shutdownMode decides what a stopping controller leaves of its node's data
// plane, from its DaemonSet ns/name. Kept only on positive confirmation that
// kloak stays (a restart, a rollout, an upgrade) with a successor that adopts
// what it keeps: the DaemonSet exists, is not being deleted, the uninstall
// hook has not annotated it, and its pod template carries
// controller.PinFormatAnnotation (a rollout to a version that does not
// would run its own data plane next to the kept one). Gone,
// being deleted, annotated, or kloak's RBAC removed (Helm deletes it with
// the release) mean an uninstall. Anything else (the API server unreachable
// within shutdownLookupTimeout) can't tell: the data plane is detached, as a
// wrong keep would leave secrets in the kernel, and a wrong detach costs only
// a gap until the next controller attaches it again. uninstalled reports
// that the controller already tore it down for an uninstall. It returns the
// mode and why, for the log.
func shutdownMode(ctx context.Context, r client.Reader, ns, name string, uninstalled bool) (mode ebpf.ShutdownMode, reason string) {
	if uninstalled {
		return ebpf.ShutdownUninstall, "the data plane was torn down for an uninstall"
	}
	ctx, cancel := context.WithTimeout(ctx, shutdownLookupTimeout)
	defer cancel()
	ds := &appsv1.DaemonSet{}
	err := r.Get(ctx, types.NamespacedName{Namespace: ns, Name: name}, ds)
	switch {
	case err == nil && ds.DeletionTimestamp != nil:
		return ebpf.ShutdownUninstall, "the DaemonSet is being deleted"
	case err == nil && ds.Annotations[controller.UninstallAnnotation] != "":
		return ebpf.ShutdownUninstall, "the DaemonSet is annotated for uninstall"
	case err == nil && ds.Spec.Template.Annotations[controller.PinFormatAnnotation] == "":
		return ebpf.ShutdownDetach, "the DaemonSet's next controllers don't adopt the eBPF objects (no " +
			controller.PinFormatAnnotation + " on its pod template: an older version, or persistence turned off)"
	case err == nil:
		return ebpf.ShutdownKeep, "the DaemonSet stays"
	case apierrors.IsNotFound(err):
		return ebpf.ShutdownUninstall, "the DaemonSet is gone"
	case apierrors.IsForbidden(err) || apierrors.IsUnauthorized(err):
		return ebpf.ShutdownUninstall, "kloak's RBAC is gone: " + err.Error()
	default:
		return ebpf.ShutdownDetach, "can't tell whether kloak stays: " + err.Error()
	}
}
