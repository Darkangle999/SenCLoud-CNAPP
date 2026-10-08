FROM golang:1.26.4-bookworm AS go-scanner-build

WORKDIR /src/scanner-go
ARG TARGETOS=linux
ARG TARGETARCH=amd64
COPY scanner-go/go.mod scanner-go/go.sum ./
RUN go mod download
COPY scanner-go/cmd/ ./cmd/
COPY scanner-go/internal/ ./internal/
RUN CGO_ENABLED=0 GOOS="${TARGETOS}" GOARCH="${TARGETARCH}" \
    go build -trimpath -ldflags="-s -w" \
    -o /out/odineyes-scanner ./cmd/odineyes-scanner

FROM python:3.11-slim

WORKDIR /app

# ── Container-image CVE scanner (Trivy) ───────────────────────────
# Pinned + integrity-verified at build, then self-pinned: the installed binary's
# own SHA256 is recorded to /etc/odineyes/trivy.sha256 and enforced at
# runtime (ODINEYES_TRIVY_SHA256_FILE), so a binary swapped after build is
# refused. See scripts/install-trivy.sh and cloud/trivy_scanner.py.
#   docker build --build-arg TRIVY_VERSION=x.y.z --build-arg TRIVY_SHA256=<sha> .
# (TRIVY_SHA256 = sha256 of trivy_<ver>_Linux-64bit.tar.gz from the release
#  checksums.txt; without it the build verifies against checksums.txt and warns.)
ARG TRIVY_VERSION=0.72.0
ARG TRIVY_SHA256=""

# ── Compliance scoring backend (Steampipe + Powerpipe) ────────────
# steampipe (AWS data) + steampipe-plugin-aws + powerpipe (runs benchmarks) +
# steampipe-mod-aws-compliance v1.13.0 (Powerpipe mod). Same self-pin posture as
# Trivy. See scripts/install-steampipe.sh and core/steampipe_runner.py.
#   docker build --build-arg STEAMPIPE_SHA256=<sha> --build-arg POWERPIPE_SHA256=<sha> .
#
# NOTE: steampipe REFUSES to run as root (plugin install + service). This RUN is
# root, so the install/runtime needs a non-root user wired in (create a user +
# pass STEAMPIPE_RUN_USER / run uvicorn as them + `steampipe service start`).
# TODO before the image is production-buildable — tracked in the design doc.
ARG STEAMPIPE_VERSION=0.24.2
ARG STEAMPIPE_SHA256=""
ARG POWERPIPE_VERSION=1.5.2
ARG POWERPIPE_SHA256=""
ARG AWS_PLUGIN_VERSION=1.28.0
ARG COMPLIANCE_MOD_VERSION=1.13.0
COPY scripts/install-trivy.sh /tmp/install-trivy.sh
COPY scripts/install-steampipe.sh /tmp/install-steampipe.sh
RUN groupadd -r cs && useradd -r -g cs -d /home/cs -m cs
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends curl ca-certificates git; \
    TRIVY_VERSION="${TRIVY_VERSION}" TRIVY_SHA256="${TRIVY_SHA256}" bash /tmp/install-trivy.sh; \
    STEAMPIPE_VERSION="${STEAMPIPE_VERSION}" STEAMPIPE_SHA256="${STEAMPIPE_SHA256}" \
      POWERPIPE_VERSION="${POWERPIPE_VERSION}" POWERPIPE_SHA256="${POWERPIPE_SHA256}" \
      AWS_PLUGIN_VERSION="${AWS_PLUGIN_VERSION}" COMPLIANCE_MOD_VERSION="${COMPLIANCE_MOD_VERSION}" \
      SUDO_USER=cs bash /tmp/install-steampipe.sh; \
    apt-get purge -y --auto-remove curl; \
    rm -rf /var/lib/apt/lists/* /tmp/install-trivy.sh /tmp/install-steampipe.sh
ENV ODINEYES_TRIVY_SHA256_FILE=/etc/cloudsentinel/trivy.sha256
ENV ODINEYES_STEAMPIPE_MOD_DIR=/opt/steampipe/aws-compliance

# Copy project metadata and pinned requirements
COPY pyproject.toml .
COPY requirements.txt .

# Install pinned dependencies for reproducible builds
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY scripts/ ./scripts/
COPY --from=go-scanner-build /out/odineyes-scanner /usr/local/bin/odineyes-scanner
ENV PYTHONPATH=/app/src

# Install the package entry point and optional AWS/database runtime extras.
RUN pip install --no-cache-dir -e ".[aws,db]"

# Non-root user — steampipe refuses root; defence-in-depth for everything else.
RUN chown -R cs:cs /app /opt/steampipe /etc/cloudsentinel 2>/dev/null || true
USER cs

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"
CMD ["uvicorn", "odineyes.api.server:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
