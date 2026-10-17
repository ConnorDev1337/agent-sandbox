#!/bin/sh
# End-to-end self-test under gVisor, inside a privileged docker:dind container.
#
# Installs a pinned gVisor release (SHA-512 checked against the published file
# and against the value pinned below), registers it as the "runsc" runtime of
# this container's own Docker daemon with --oci-seccomp, and runs
# `agent-sandbox verify --build` for every runtime in $RUNTIMES and every
# TLS inspection mode in $TLS_MODES. The CLI runs next to the daemon, in the
# same container, so the bind mounts of the generated Compose file resolve.
#
# Never run this on a host whose Docker daemon you care about: it rewrites
# /etc/docker/daemon.json and reloads dockerd.
#
# Usage: sh scripts/e2e-dind.sh [SOURCE_DIR]    (default: the current directory)
#
# GVISOR_PLATFORM selects the gVisor platform. The default, systrap, needs its
# own seccomp user-notification listener and fails ("failed to create a
# syscall thread") where an ancestor process already holds one, as under
# Docker Desktop on WSL2; use GVISOR_PLATFORM=ptrace there.
set -eu

SOURCE_DIR="$(cd "${1:-.}" && pwd)"
# The first release that honours errnoRet in OCI seccomp profiles: older ones
# return EPERM for clone3 instead of ENOSYS, and glibc then cannot start threads.
GVISOR_VERSION="${GVISOR_VERSION:-20261012.0}"
GVISOR_CACHE="${GVISOR_CACHE:-/var/cache/gvisor}"
GVISOR_PLATFORM="${GVISOR_PLATFORM:-systrap}"
RUNTIMES="${RUNTIMES-runsc runc}"
TLS_MODES="${TLS_MODES-false true}"
WORK_DIR="${WORK_DIR:-/tmp/agent-sandbox-e2e}"

# SHA-512 of gvisor.tar.zstd for GVISOR_VERSION, per architecture.
case "$(uname -m)" in
    x86_64)
        ARCH=x86_64
        GVISOR_SHA512=ce2e1aeb853c104e854dea6644333a1dba0fbc9dd1646af97e1d013fdf810da6d4176dd96f2139d7b055e5382117c0d7c4567ebd64ed9bef47fdd15f80fd67ab
        ;;
    aarch64)
        ARCH=aarch64
        GVISOR_SHA512=3459ca3e496465e5b6a1318563ede4bb079bdf11ae93f4bb8d71df3cd2f19bfa6db7c1035d2f9e97b4f4e57c298a4f18b42af7297c048ec7e14ec819223684e4
        ;;
    *)
        echo "unsupported architecture: $(uname -m)" >&2
        exit 2
        ;;
esac

log() {
    printf '\n=== %s\n' "$*"
}

install_packages() {
    log "installing packages"
    apk add --no-cache python3 py3-pip tar zstd >/dev/null
}

install_gvisor() {
    url="https://storage.googleapis.com/gvisor/releases/release/${GVISOR_VERSION}/${ARCH}"
    dir="${GVISOR_CACHE}/${GVISOR_VERSION}/${ARCH}"
    log "installing gVisor ${GVISOR_VERSION} (${ARCH})"
    mkdir -p "$dir"
    if [ ! -s "$dir/gvisor.tar.zstd" ]; then
        wget -q -O "$dir/gvisor.tar.zstd.part" "$url/gvisor.tar.zstd"
        mv "$dir/gvisor.tar.zstd.part" "$dir/gvisor.tar.zstd"
    fi
    wget -q -O "$dir/gvisor.tar.zstd.sha512" "$url/gvisor.tar.zstd.sha512"
    published="$(cut -d' ' -f1 "$dir/gvisor.tar.zstd.sha512")"
    if [ "$published" != "$GVISOR_SHA512" ]; then
        echo "published SHA-512 $published differs from the pinned $GVISOR_SHA512" >&2
        exit 1
    fi
    (cd "$dir" && sha512sum -c gvisor.tar.zstd.sha512)
    tar --zstd -xf "$dir/gvisor.tar.zstd" -C /usr/local/bin
    /usr/local/bin/runsc --version
}

docker_ready() {
    docker info >/dev/null 2>&1
}

runsc_ready() {
    docker_ready && docker info --format '{{json .Runtimes}}' | grep -q '"runsc"'
}

wait_for() {
    what="$1"
    shift
    tries=0
    until "$@"; do
        tries=$((tries + 1))
        if [ "$tries" -gt 60 ]; then
            echo "timed out waiting for $what" >&2
            tail -n 50 /var/log/dockerd.log >&2 || true
            exit 1
        fi
        sleep 1
    done
}

register_runsc() {
    log "registering runsc in this container's Docker daemon"
    # The OCI seccomp profile is ignored by runsc unless --oci-seccomp is set.
    /usr/local/bin/runsc install --runtime runsc -- --oci-seccomp --platform="$GVISOR_PLATFORM"
    cat /etc/docker/daemon.json
    echo
    if pidof dockerd >/dev/null; then
        # Started by the image's entrypoint: wait for it, then reload its runtimes.
        wait_for dockerd docker_ready
        kill -HUP "$(pidof dockerd)"
    else
        DOCKER_TLS_CERTDIR="" dockerd-entrypoint.sh dockerd >/var/log/dockerd.log 2>&1 &
    fi
    wait_for "the runsc runtime" runsc_ready
    docker info --format 'docker {{.ServerVersion}}, kernel {{.KernelVersion}}, cgroup v{{.CgroupVersion}}'
}

install_cli() {
    log "installing agent-sandbox from ${SOURCE_DIR}"
    rm -rf "$WORK_DIR/src"
    mkdir -p "$WORK_DIR"
    cp -R "$SOURCE_DIR" "$WORK_DIR/src"
    python3 -m pip install --quiet --break-system-packages --no-cache-dir "$WORK_DIR/src"
}

verify() {
    runtime="$1"
    tls="$2"
    workspace="$WORK_DIR/ws-$runtime-tls-$tls"
    log "verify: runtime=$runtime tls_inspect=$tls"
    rm -rf "$workspace"
    mkdir -p "$workspace"
    git -C "$workspace" init -q
    cat >"$workspace/.agent-sandbox.toml" <<EOF
[sandbox]
runtime = "$runtime"

[network]
tls_inspect = $tls
allow = [{ host = "github.com", methods = ["GET", "HEAD"] }]
EOF
    status=0
    agent-sandbox -w "$workspace" verify --build || status=$?
    if [ "$status" -ne 0 ]; then
        agent-sandbox -w "$workspace" alerts --events -n 200 || true
        project="$(agent-sandbox -w "$workspace" config | python3 -c \
            'import json, sys; print(json.load(sys.stdin)["project"])')" || project=""
        [ -z "$project" ] || docker compose -p "$project" logs --no-color --tail 100 || true
    fi
    agent-sandbox -w "$workspace" down --volumes || true
    RESULTS="${RESULTS}runtime=$runtime tls_inspect=$tls exit=$status
"
    [ "$status" -eq 0 ] || FAILED=1
}

install_packages
install_gvisor
register_runsc
install_cli

RESULTS=""
FAILED=0
for runtime in $RUNTIMES; do
    for tls in $TLS_MODES; do
        verify "$runtime" "$tls"
    done
done

log "summary"
printf '%s' "$RESULTS"
exit "$FAILED"
