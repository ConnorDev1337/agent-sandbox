# Egress gateway: allowlist proxy, DNS sinkhole and canary tripwires.
# Build context: the agent_sandbox package directory.
FROM python:3.14-slim-bookworm@sha256:48b13b003dda20b16f9442b8475aa05fe21bf6579a8c881db92ffb4d8fd20f83

# openssl mints the per-sandbox CA and leaf certificates for TLS inspection.
# The base image already ships it (ca-certificates depends on it); installing
# the exact version keeps the dependency explicit, and a base image update
# that changes it fails here instead of going unnoticed.
ARG OPENSSL_VERSION=3.0.22-1~deb12u1
RUN apt-get update \
    && apt-get install -y --no-install-recommends "openssl=${OPENSSL_VERSION}" \
    && rm -rf /var/lib/apt/lists/* \
    && openssl version

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/agent-sandbox

COPY . /opt/agent-sandbox/agent_sandbox

EXPOSE 3128/tcp 53/udp
ENTRYPOINT ["python", "-m", "agent_sandbox.gateway"]
