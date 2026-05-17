#!/usr/bin/env bash
# klor installer — drops a cap'd `klor` binary into /usr/local/bin so it
# runs without `sudo` per invocation.
#
# Usage:
#   ./install.sh                              # checkout-local: build from source
#   curl -fsSL https://.../install.sh | bash  # release: pull latest tagged binary
#   ./install.sh --version v0.1.2             # release: pull a specific tag
#   ./install.sh --prefix /opt/klor/bin       # install under a different bindir
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
KLOR_SOURCE_BINARY=""  # set by env override (KLOR_BINARY=...) for testing

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

# -----------------------------------------------------------------------
# Privilege escalation: re-exec under sudo when we need it
# -----------------------------------------------------------------------
#
# We escalate up-front rather than partway through. Two reasons:
#  1. Curl|bash pipes can't accept stdin for sudo's password prompt
#     mid-script; getting the password before any work means the user
#     sees the prompt at a predictable moment.
#  2. The `cp` + `setcap` + `getcap verify` block needs to be atomic — if
#     we re-exec mid-stream we'd lose state (resolved binary path, etc.).

if [[ $EUID -ne 0 ]]; then
    log "klor installer needs root to write to $PREFIX and set file capabilities."
    log "Re-executing under sudo …"
    # -E so the user's env (KLOR_BINARY override, HOME for go cache, …)
    # survives into the privileged context.
    exec sudo -E "$0" --prefix "$PREFIX" --version "$VERSION"
fi

# -----------------------------------------------------------------------
# Locate or build the klor binary
# -----------------------------------------------------------------------

# Resolve the script directory (handle bash/zsh + symlinks).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"

resolve_binary() {
    # 1. Explicit env override — used by the rooted e2e test and anyone
    #    who's pre-built klor themselves.
    if [[ -n "${KLOR_BINARY:-}" ]]; then
        [[ -x "$KLOR_BINARY" ]] || die "KLOR_BINARY=$KLOR_BINARY is not an executable"
        echo "$KLOR_BINARY"
        return
    fi

    # 2. Checkout-local build — if cmd/klor/ exists next to install.sh,
    #    assume this is a developer running from a git clone and build
    #    from source. Lets contributors validate install.sh without
    #    cutting a release.
    if [[ -d "$SCRIPT_DIR/cmd/klor" ]]; then
        log "Detected source checkout at $SCRIPT_DIR — building klor locally …"
        command -v go >/dev/null || die "go not installed (needed to build from checkout)"
        local out
        out="$(mktemp -d)/klor"
        (cd "$SCRIPT_DIR" && go build -o "$out" ./cmd/klor) || die "go build failed"
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
        *) die "unsupported architecture $(uname -m) — klor ships amd64 and arm64 only" ;;
    esac
    [[ "$os" == "linux" ]] || die "klor's host-cgroup runtime is Linux-only (got $os)"

    if [[ "$VERSION" == "latest" ]]; then
        tag="$(curl -fsSL "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/releases/latest" \
            | grep -m1 '"tag_name":' | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')"
        [[ -n "$tag" ]] || die "could not resolve 'latest' tag from GitHub releases API"
    else
        tag="$VERSION"
    fi

    tar_name="klor-${os}-${arch}.tar.gz"
    url="https://github.com/$REPO_OWNER/$REPO_NAME/releases/download/$tag/$tar_name"
    tmp="$(mktemp -d)"

    log "Fetching klor $tag for $os/$arch …"
    curl -fsSL --output "$tmp/$tar_name"        "$url"        || die "download failed: $url"
    curl -fsSL --output "$tmp/$tar_name.sha256" "$url.sha256" || die "download failed: $url.sha256"

    # Verify the checksum. The sha256 sidecar format mirrors what
    # `sha256sum` produces ("<hash>  <filename>") so the standard
    # verifier can validate it without parsing.
    (cd "$tmp" && sha256sum -c "$tar_name.sha256") >/dev/null \
        || die "sha256 mismatch — refusing to install"

    tar -xzf "$tmp/$tar_name" -C "$tmp" || die "tar extraction failed"
    [[ -x "$tmp/klor" ]] || die "extracted archive doesn't contain an executable 'klor'"

    echo "$tmp/klor"
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
    # CAP_SYS_ADMIN klor would EPERM at the parent-write check before
    # the cgroup hook gets a chance to authorize the operation.
    #
    # Together this is still strictly less than what `sudo` gives the
    # binary (sudo is "all caps") — DAC_OVERRIDE means klor can
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
    local dest="$PREFIX/klor"

    command -v setcap >/dev/null \
        || die "setcap not installed (apt: libcap2-bin; rpm: libcap; alpine: libcap-setcap)"
    command -v getcap >/dev/null \
        || die "getcap not installed (same package as setcap)"

    log "Installing $dest …"
    mkdir -p "$PREFIX"
    install -m 0755 "$src" "$dest"

    log "Setting capabilities: $capset"
    if ! setcap "$capset" "$dest"; then
        # AppArmor, SELinux, or NFS-without-acl can reject setcap. Don't
        # leave a half-installed binary behind that would mislead the
        # user into thinking klor is ready when it can't actually run.
        rm -f "$dest"
        die "setcap rejected the capability set — your kernel or LSM may not allow file capabilities here"
    fi

    # Verify the caps actually stuck. Some filesystems silently strip
    # them at write time (NFS without `acl` mount option is the common
    # culprit). getcap returns 0 with empty output in that case.
    local got
    got="$(getcap "$dest" 2>/dev/null | awk '{ $1=""; sub(/^ /,""); print }')"
    if [[ -z "$got" ]]; then
        rm -f "$dest"
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

${c_green}✓${c_reset} klor installed.

  $ klor run --secrets ./secrets.yaml -- curl https://api.example.com/...

No sudo needed for normal invocations.

EOF
