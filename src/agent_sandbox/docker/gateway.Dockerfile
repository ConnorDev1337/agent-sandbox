# Egress gateway: allowlist proxy, DNS sinkhole and canary tripwires.
# Build context: the agent_sandbox package directory.
FROM python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/opt/agent-sandbox

COPY . /opt/agent-sandbox/agent_sandbox

EXPOSE 3128/tcp 53/udp
ENTRYPOINT ["python", "-m", "agent_sandbox.gateway"]
