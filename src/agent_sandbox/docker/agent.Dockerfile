# Default agent image: common tooling for coding agents, running as uid 1000.
# Build context: the agent_sandbox package directory.

# Node.js 22 LTS, taken from the official image for the same Debian release.
# Debian's own package is Node.js 18, whose built-in fetch ignores HTTP(S)_PROXY;
# from 22.21 on, NODE_USE_ENV_PROXY=1 (set by the Compose file) routes it
# through the gateway.
FROM node:22-bookworm-slim@sha256:c3de60bf2f9dd0ac6370e6117950ff62d6e339527e7472301c9c78a017978392 AS node

FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash ca-certificates curl git jq less procps \
        python3 python3-pip python3-venv ripgrep \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --create-home --shell /bin/bash agent

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules/npm /usr/local/lib/node_modules/npm
RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
    && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
    && node --version && npm --version

COPY selftest.py /opt/agent-sandbox/selftest.py

ENV HOME=/home/agent
USER agent
WORKDIR /workspace
CMD ["sleep", "infinity"]
