#!/usr/bin/env bash
# krunk installer — drops a cap'd `krunk` binary into /usr/local/bin so it
# runs without `sudo` per invocation.
#
# Usage:
#   ./install.sh                              # checkout-local: build from source
#   curl -fsSL https://.../install.sh | bash  # release: pull latest tagged binary
#   ./install.sh --version v0.1.2             # release: pull a specific tag
#   ./install.sh --prefix /opt/krunk/bin       # install under a different bindir
#
# Privilege handling: the installer starts as whoever invoked it, then
# re-execs itself under `sudo` for the cp + setcap steps. Curl|bash users
# get a single sudo prompt at the right moment; CI pipelines that
# already run as root short-circuit it.
#
# The capability set is chosen based on the running kernel:
#   kernel ≥ 5.8:   cap_sys_admin,cap_bpf,cap_perfmon,cap_net_admin+ep
#   kernel  < 5.8:  cap_sys_admin+ep
# CAP_SYS_ADMIN is needed today for cgroup-v2 mkdir under
# /sys/fs/cgroup. The other three line up with the eBPF wiring
# follow-up — granting them now means the binary doesn't need a
# re-install when that lands.

set -euo pipefail

# -----------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------

readonly REPO_OWNER="spinningfactory"
readonly REPO_NAME="kloak"

PREFIX="/usr/local/bin"
VERSION="latest"
KRUNK_SOURCE_BINARY=""  # set by env override (KRUNK_BINARY=...) for testing

# -----------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------

c_reset="\033[0m"
c_green="\033[1;32m"
c_yellow="\033[1;33m"
c_red="\033[1;31m"
if [[ ! -t 1 ]]; then c_reset=""; c_green=""; c_yellow=""; c_red=""; fi

# All log helpers write to stderr so functions can freely `echo "$result"`
# on stdout for command substitution without log lines leaking into the
# captured value.
log()  { printf "%b==>%b %s\n" "$c_green"  "$c_reset" "$*" >&2; }
warn() { printf "%bWARNING:%b %s\n" "$c_yellow" "$c_reset" "$*" >&2; }
die()  { printf "%berror:%b %s\n"   "$c_red"    "$c_reset" "$*" >&2; exit 1; }

# -----------------------------------------------------------------------
# Argument parsing
# -----------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="${2:?--version requires an argument}"; shift 2 ;;
        --prefix)  PREFIX="${2:?--prefix requires an argument}";   shift 2 ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# //; s/^#//'
            exit 0
            ;;
        *) die "unknown argument: $1 (use --help for usage)" ;;
    esac
done

readonly PREFIX VERSION

# Tempdirs for build output / release tarball / etc. We collect them
# all in a single bash array and `trap … EXIT` clears them on any exit
# path (success, error, signal). Without this, a `--version foo` typo
# would leave megabytes of downloaded tarballs in /tmp.
_TMPDIRS=()
make_tempdir() {
    local d
    d="$(mktemp -d)"
    _TMPDIRS+=("$d")
    echo "$d"
}
trap '[[ ${#_TMPDIRS[@]} -gt 0 ]] && rm -rf "${_TMPDIRS[@]}"' EXIT

# -----------------------------------------------------------------------
# Privilege escalation strategy
# -----------------------------------------------------------------------
#
# We need root for three operations: writing to $PREFIX (typically
# /usr/local/bin), `setcap` (needs CAP_SETFCAP), and the install/mkdir
# under root-owned paths. Everything else — resolving the binary,
# building from source, downloading the release tarball — should run as
# the *invoking* user, not as root. Two reasons:
#
#   1. `go build` writes to the user's Go cache (~/.cache/go-build,
#      ~/go/pkg). Running it as root via `sudo -E` would either reach
#      into the user's $HOME (creating root-owned cache files that the
#      user can't later read/update from their normal shell — gemini
#      caught this) or to root's own cache, which is uselessly empty.
#   2. Curl-piped downloads + sha256 verification have no reason to
#      run privileged; doing them as root only widens the blast radius
#      if anything goes wrong before `setcap`.
#
# So: the script stays as the invoking user, and individual privileged
# steps re-acquire root via `sudo` (or run directly when we're already
# root, e.g., in an apt/yum postinst). The early `sudo -n true` probe
# tells us up-front whether the user will hit a password prompt later —
# that matters because curl|bash invocations have no controlling tty
# and can't accept a password mid-stream.

# privileged_run executes the given command as root: directly when we're
# already root (apt/yum postinst, deliberate `sudo bash install.sh`),
# via `sudo` otherwise. Stdin is closed for these calls so a misbehaving
# command can't sit waiting on input.
privileged_run() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    else
        sudo -n "$@" </dev/null
    fi
}

# Probe for the privilege we'll need. Fails loud BEFORE any work if
# sudo would prompt and we have no tty to accept the password (curl|sh
# case) — running into that mid-script after a long download or build
# is a worse user experience than refusing up-front.
if [[ $EUID -ne 0 ]]; then
    command -v sudo >/dev/null || die "sudo not available and not running as root — re-run as root or in an environment with sudo"
    if ! sudo -n true 2>/dev/null; then
        if [[ ! -t 0 ]]; then
            die "this script needs sudo but no tty is available for a password prompt. Re-run as: curl … | sudo bash"
        fi
        log "Privileged steps (install + setcap) will prompt for your sudo password."
    fi
fi

# -----------------------------------------------------------------------
# Locate or build the krunk binary
# -----------------------------------------------------------------------

# Resolve the script directory (handle bash/zsh + symlinks).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

resolve_binary() {
    # 1. Explicit env override — used by the rooted e2e test and anyone
    #    who's pre-built krunk themselves.
    if [[ -n "${KRUNK_BINARY:-}" ]]; then
        [[ -x "$KRUNK_BINARY" ]] || die "KRUNK_BINARY=$KRUNK_BINARY is not an executable"
        echo "$KRUNK_BINARY"
        return
    fi

    # 2. Checkout-local build — if cmd/krunk/ exists next to install.sh,
    #    assume this is a developer running from a git clone and build
    #    from source. Lets contributors validate install.sh without
    #    cutting a release.
    if [[ -d "$SCRIPT_DIR/cmd/krunk" ]]; then
        log "Detected source checkout at $SCRIPT_DIR — building krunk locally …"
        command -v go    >/dev/null || die "go not installed (needed to build from checkout)"
        command -v clang >/dev/null || die "clang not installed (needed to compile eBPF programs); install clang or use a release tarball"

        # Regenerate the eBPF bindings BEFORE building. The .o files
        # under pkg/ebpf/ are gitignored AND embedded into the Go
        # binding via //go:embed, so a stale .o from a previous
        # generate gets baked into krunk — even on a fresh `go build`.
        # We hit this on the kloak: → kl:: prefix rename: krunk built
        # cleanly but the embedded BPF matcher still looked for
        # "kloak:", so it never matched the new shadows on the wire.
        # Always regenerate from checkout so the binary's BPF is in
        # sync with the .c source the user has checked out.
        #
        # KLOAK_TARGET_ARCH selects which `#if defined(bpf_target_*)`
        # branches in tls_uprobe.c are live — those branches contain
        # arch-specific register-offset reads (RDI/RSI/RDX on x86 vs
        # X0/X1/X2 on arm64) for unwrapping the SSL_write arguments
        # from the uprobe trap frame. A mismatch silently breaks
        # every uprobe: ssl_ptr and data_ptr come back as garbage and
        # the early NULL/<=0 checks bail. Detect from `uname -m` so
        # the same install.sh works on Apple-Silicon Lima VMs
        # (aarch64) and on amd64 production boxes alike.
        local arch_uname target_arch
        arch_uname="$(uname -m)"
        case "$arch_uname" in
            x86_64|amd64)  target_arch=x86 ;;
            aarch64|arm64) target_arch=arm64 ;;
            *) die "unsupported architecture for eBPF codegen: $arch_uname" ;;
        esac
        log "Regenerating eBPF bindings (go generate ./pkg/ebpf/, KLOAK_TARGET_ARCH=$target_arch) …"
        (cd "$SCRIPT_DIR" && KLOAK_TARGET_ARCH="$target_arch" go generate ./pkg/ebpf/) \
            || die "go generate ./pkg/ebpf/ failed — check clang version and BPF headers"

        local out
        out="$(make_tempdir)/krunk"
        # Run as the invoking user (not root) — `go build` writes the
        # build cache under $HOME; doing it as root either reaches into
        # the user's HOME and leaves root-owned cache files there, or
        # writes to root's own cache, which is useless. We're not root
        # here yet (we only escalate at install time) so this is
        # already correct, but keep the comment as a reminder for
        # future refactors.
        #
        # KRUNK_COVER=1 (CI's Krunk E2E job) builds a coverage-
        # instrumented binary so the cap'd krunk's runtime coverage
        # contributes back to the merged profile. `-cover` arms
        # runtime/coverage, `-covermode=atomic` makes counters safe
        # under krunk's background pollers, `-tags cover` pulls in
        # cmd/krunk/coverage_flush_cover.go which writes covcounters
        # to $GOCOVERDIR on exit (Go's auto-flush is unreliable for
        # os.Exit paths, which krunk uses for exit-code propagation).
        local build_args=("-o" "$out")
        if [[ "${KRUNK_COVER:-0}" = "1" ]]; then
            log "KRUNK_COVER=1 — building krunk with -cover instrumentation"
            build_args+=("-cover" "-covermode=atomic" "-tags" "cover")
        fi
        (cd "$SCRIPT_DIR" && go build "${build_args[@]}" ./cmd/krunk) || die "go build failed"
        echo "$out"
        return
    fi

    # 3. Release tarball — pull from GitHub.
    download_release_binary
}

download_release_binary() {
    command -v curl    >/dev/null || die "curl not installed"
    command -v tar     >/dev/null || die "tar not installed"
    command -v sha256sum >/dev/null || die "sha256sum not installed"

    local os arch tag tar_name url tmp
    os="$(uname -s | tr '[:upper:]' '[:lower:]')"
    case "$(uname -m)" in
        x86_64|amd64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) die "unsupported architecture $(uname -m) — krunk ships amd64 and arm64 only" ;;
    esac
    [[ "$os" == "linux" ]] || die "krunk's host-cgroup runtime is Linux-only (got $os)"

    if [[ "$VERSION" == "latest" ]]; then
        tag="$(curl -fsSL "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/latest" \
            | grep -m1 '"tag_name":' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
        [[ -n "$tag" ]] || die "could not resolve 'latest' tag from GitHub releases API"
    else
        tag="$VERSION"
    fi

    tar_name="krunk-${os}-${arch}.tar.gz"
    url="https://github.com/$REPO_OWNER/$REPO_NAME/releases/download/$tag/$tar_name"
    tmp="$(make_tempdir)"

    log "Fetching krunk $tag for $os/$arch …"
    curl -fsSL --output "$tmp/$tar_name"        "$url"        || die "download failed: $url"
    curl -fsSL --output "$tmp/$tar_name.sha256" "$url.sha256" || die "download failed: $url.sha256"

    # Verify the checksum. The sha256 sidecar format mirrors what
    # `sha256sum` produces ("<hash>  <filename>") so the standard
    # verifier can validate it without parsing.
    (cd "$tmp" && sha256sum -c "$tar_name.sha256") >/dev/null \
        || die "sha256 mismatch — refusing to install"

    tar -xzf "$tmp/$tar_name" -C "$tmp" || die "tar extraction failed"
    [[ -x "$tmp/krunk" ]] || die "extracted archive doesn't contain an executable 'krunk'"

    echo "$tmp/krunk"
}

# -----------------------------------------------------------------------
# Capability set selection
# -----------------------------------------------------------------------

choose_capset() {
    # Linux 5.8 introduced CAP_BPF / CAP_PERFMON as distinct caps. On
    # older kernels granting them is a no-op (the kernel doesn't know
    # those bit positions), so we fall back to a single CAP_SYS_ADMIN.
    local kernel major minor
    kernel="$(uname -r)"
    major="${kernel%%.*}"
    minor="${kernel#*.}"
    minor="${minor%%.*}"

    # printf %d barfs on non-numeric input; bail gracefully to the
    # broad capset for unusual kernels.
    if ! [[ "$major" =~ ^[0-9]+$ && "$minor" =~ ^[0-9]+$ ]]; then
        warn "could not parse kernel version '$kernel' — using cap_sys_admin only"
        echo "cap_sys_admin+ep"
        return
    fi

    # CAP_SYS_ADMIN authorizes the cgroup-layer operations (mkdir hook,
    # cross-cgroup process migration). CAP_DAC_OVERRIDE is the extra
    # piece that bypasses the VFS DAC check on the root-owned
    # `/sys/fs/cgroup/...` parent directories and on the per-cgroup
    # `cgroup.procs` files (mode 0644). Without DAC_OVERRIDE, even a
    # CAP_SYS_ADMIN krunk would EPERM at the parent-write check before
    # the cgroup hook gets a chance to authorize the operation.
    #
    # Together this is still strictly less than what `sudo` gives the
    # binary (sudo is "all caps") — DAC_OVERRIDE means krunk can
    # read/write/execute any file on the system regardless of mode
    # bits, but it stays as the invoking user (no setuid, no CAP_CHOWN,
    # no CAP_SYS_PTRACE, …).
    if (( major > 5 )) || (( major == 5 && minor >= 8 )); then
        echo "cap_dac_override,cap_sys_admin,cap_bpf,cap_perfmon,cap_net_admin+ep"
    else
        echo "cap_dac_override,cap_sys_admin+ep"
    fi
}

# -----------------------------------------------------------------------
# Install + setcap + verify
# -----------------------------------------------------------------------

install_binary() {
    local src="$1" capset="$2"
    local dest="$PREFIX/krunk"

    command -v setcap >/dev/null \
        || die "setcap not installed (apt: libcap2-bin; rpm: libcap; alpine: libcap-setcap)"
    command -v getcap >/dev/null \
        || die "getcap not installed (same package as setcap)"

    # Each privileged step goes through `privileged_run` so install.sh
    # itself stays as the invoking user; `sudo` is acquired only for
    # the operations that genuinely need root (write to $PREFIX,
    # `setcap`). `install` does both the mkdir and the file copy in
    # one syscall — fewer privileged calls is less attack surface.
    log "Installing $dest …"
    privileged_run install -m 0755 -D "$src" "$dest" \
        || die "install to $dest failed"

    log "Setting capabilities: $capset"
    if ! privileged_run setcap "$capset" "$dest"; then
        # AppArmor, SELinux, or NFS-without-acl can reject setcap. Don't
        # leave a half-installed binary behind that would mislead the
        # user into thinking krunk is ready when it can't actually run.
        privileged_run rm -f "$dest"
        die "setcap rejected the capability set — your kernel or LSM may not allow file capabilities here"
    fi

    # Verify the caps actually stuck. Some filesystems silently strip
    # them at write time (NFS without `acl` mount option is the common
    # culprit). getcap doesn't need root — readable by anyone. Returns
    # 0 with empty output in the strip case, so we check the output
    # rather than the exit code.
    local got
    got="$(getcap "$dest" 2>/dev/null | awk '{ $1=""; sub(/^ /,""); print }')"
    if [[ -z "$got" ]]; then
        privileged_run rm -f "$dest"
        die "capabilities did not persist on $dest — filesystem may be stripping them (NFS without acl, AppArmor, …)"
    fi
    log "Verified capabilities on $dest: $got"
}


# -----------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------

binary="$(resolve_binary)"
capset="$(choose_capset)"
install_binary "$binary" "$capset"

cat <<EOF

${c_green}✓${c_reset} krunk installed.

  $ krunk run --secrets ./secrets.yaml -- curl https://api.example.com/...

EOF
