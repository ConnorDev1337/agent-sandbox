# Demo agent image for the defense-in-depth example.
#
# It builds wheels for tool-call-guard and mcp-security-scanner from the local
# sibling checkouts (copied into the build context by the demo driver) and installs
# them on top of the base agent-sandbox agent image, which already runs as uid 1000
# with a read-only root filesystem, Node.js and the self-test. The base image tag is
# passed in by the driver and is itself built from pinned base-image digests.
#
# Build context: a directory containing tool-call-guard/ and mcp-security-scanner/.

# Wheels builder. Pinned to the same Python base image the gateway uses.
FROM python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641 AS wheels
WORKDIR /build
COPY tool-call-guard /build/tool-call-guard
COPY mcp-security-scanner /build/mcp-security-scanner
RUN python -m pip wheel --no-deps -w /wheels \
        /build/tool-call-guard /build/mcp-security-scanner

ARG BASE_IMAGE=agent-sandbox-demo/agent-base:defense-in-depth
FROM ${BASE_IMAGE}

# Install the two tools from the locally built wheels (no index, no network). The
# base image's Python is Debian's system interpreter, so --break-system-packages is
# needed; both packages have no runtime dependencies.
USER root
COPY --from=wheels /wheels /tmp/wheels
RUN python3 -m pip install --break-system-packages --no-index --find-links=/tmp/wheels \
        tool-call-guard mcp-security-scanner \
    && rm -rf /tmp/wheels \
    && toolguard --version \
    && mcp-scanner --version

USER agent
