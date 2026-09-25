# Vantage DAST control-plane image (Debian slim).
#
# This image contains only Vantage's own code plus its permissive Python
# dependencies. External security engines are NOT baked in here; they run either
# as isolated sidecar containers (DockerSandboxRunner) or as native binaries on
# a host/Kali deployment (LocalSubprocessRunner). This keeps the control-plane
# image free of copyleft/commercial engine code.
FROM python:3.12-slim AS build

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip && pip install .

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
# Run as non-root.
RUN useradd --system --uid 10001 --create-home vantage
COPY --from=build /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=build /usr/local/bin /usr/local/bin
WORKDIR /app
COPY engines ./engines
COPY third_party ./third_party
USER vantage
EXPOSE 8080
# The control plane; scans dispatch engines to the configured sandbox.
ENTRYPOINT ["uvicorn", "vantage.api.app:app", "--host", "0.0.0.0", "--port", "8080"]
