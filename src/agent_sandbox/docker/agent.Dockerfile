# Default agent image: common tooling for coding agents, running as uid 1000.
# Build context: the agent_sandbox package directory.
FROM debian:bookworm-slim@sha256:7c7b2c966bc9ee8cedfeef67e0e279108992c77681fa595db4a9d65c06ccc587

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash ca-certificates curl git jq less nodejs npm procps \
        python3 python3-pip python3-venv ripgrep \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 1000 --create-home --shell /bin/bash agent

COPY selftest.py /opt/agent-sandbox/selftest.py

ENV HOME=/home/agent
USER agent
WORKDIR /workspace
CMD ["sleep", "infinity"]
