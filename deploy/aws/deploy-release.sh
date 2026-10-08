#!/usr/bin/env bash
# Keep this script LF-terminated: AWS SSM executes it with Bash on Amazon Linux.
# Deploy an already-built Odineyes release bundle on the single EC2 host.
# Called through SSM Run Command. It never reads dashboard credentials: it
# preserves the existing generated Caddyfile and environment file instead.
set -euo pipefail

release_bucket="${1:?usage: deploy-release.sh <release-bucket> <release-key> [region]}"
release_key="${2:?usage: deploy-release.sh <release-bucket> <release-key> [region]}"
region="${3:-us-east-1}"

app_root=/opt/odineyes
release_name="$(basename "$release_key" .zip)"
staging_root="/opt/.${release_name}"
previous_root="/opt/odineyes-previous-${release_name}"
failed_root="/opt/odineyes-failed-${release_name}"
backup_root=/opt/odineyes-backups
release_zip="/tmp/${release_name}.zip"
api_previous=odineyes-api-previous
web_previous=odineyes-web-previous
realtime_previous=odineyes-realtime-previous
image_tag="odineyes-api:${release_name}"

test -f "$app_root/odineyes.env"
test -f "$app_root/deploy/aws/Caddyfile"
rm -rf "$staging_root"
mkdir -p "$staging_root" "$backup_root"

aws s3 cp "s3://${release_bucket}/${release_key}" "$release_zip" --region "$region"
unzip -q "$release_zip" -d "$staging_root"
test -f "$staging_root/deploy/aws/Dockerfile.runtime"
test -f "$staging_root/frontend/dist/index.html"
# Windows ZIP creation does not preserve the Linux executable bit. The runtime
# Dockerfile applies chmod 0555 after COPY, so presence is the valid preflight.
test -f "$staging_root/scanner-go/bin/odineyes-scanner-linux-amd64"
test -f "$staging_root/scanner-go/bin/odineyes-graph-linux-amd64"
test -f "$staging_root/scanner-go/bin/odineyes-realtime-linux-amd64"

# ponytail: 1 GB of RAM cannot hold `docker build` and the live containers at
# once. On 2026-08-04 the OOM killer took out both containers *and* the SSM
# agent mid-build, so the deploy hung with the site returning 504 and no way to
# ask the box why. Swap is the smallest fix that preserves the ordering below —
# build first, swap containers only once it succeeds. Idempotent, and it runs
# before anything is stopped, so a failure here leaves production untouched.
if ! swapon --show=NAME --noheadings 2>/dev/null | grep -qx /swapfile; then
  [ -f /swapfile ] || fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
  chmod 600 /swapfile
  mkswap /swapfile >/dev/null
  swapon /swapfile
  grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

# Build without touching running containers. A failed build leaves production up.
docker build -t "$image_tag" -f "$staging_root/deploy/aws/Dockerfile.runtime" "$staging_root"

# Keep durable scan/onboarding state plus a timestamped recoverable backup.
tar -C "$app_root" -czf "$backup_root/${release_name}-data.tar.gz" data
cp -a "$app_root/data" "$staging_root/data"
cp "$app_root/odineyes.env" "$staging_root/odineyes.env"
cp "$app_root/deploy/aws/Caddyfile" "$staging_root/deploy/aws/Caddyfile"
# Existing hosts preserve their generated basic-auth hash. Add the new route
# idempotently instead of replacing that credential-bearing Caddyfile.
if grep -q 'handle_path /api/realtime/\*' "$staging_root/deploy/aws/Caddyfile"; then
  sed -i '/^[[:space:]]*handle_path \/api\/realtime\/\* {$/,/^[[:space:]]*}$/c\    @realtime path /api/realtime/ws /api/realtime/health\n    handle @realtime {\n        uri strip_prefix /api/realtime\n        reverse_proxy odineyes-realtime:8090\n    }' "$staging_root/deploy/aws/Caddyfile"
elif ! grep -q '@realtime path /api/realtime/ws' "$staging_root/deploy/aws/Caddyfile"; then
  sed -i '/^[[:space:]]*@api path \/api\/\*/i\    @realtime path /api/realtime/ws /api/realtime/health\n    handle @realtime {\n        uri strip_prefix /api/realtime\n        reverse_proxy odineyes-realtime:8090\n    }\n' "$staging_root/deploy/aws/Caddyfile"
fi
# Hosts created before the Go graph engine existed do not have its rollout
# settings. Add safe defaults only when absent; explicit operator choices are
# preserved across releases.
grep -q '^ODINEYES_GRAPH_ENGINE=' "$staging_root/odineyes.env" || \
  printf '\nODINEYES_GRAPH_ENGINE=auto\n' >> "$staging_root/odineyes.env"
grep -q '^ODINEYES_GRAPH_GO_MIN_ASSETS=' "$staging_root/odineyes.env" || \
  printf 'ODINEYES_GRAPH_GO_MIN_ASSETS=1000\n' >> "$staging_root/odineyes.env"
grep -q '^ODINEYES_TRIVY_VM_TIMEOUT_SECONDS=' "$staging_root/odineyes.env" || \
  printf 'ODINEYES_TRIVY_VM_TIMEOUT_SECONDS=1800\n' >> "$staging_root/odineyes.env"
grep -q '^ODINEYES_EBS_SCAN_COOLDOWN_HOURS=' "$staging_root/odineyes.env" || \
  printf 'ODINEYES_EBS_SCAN_COOLDOWN_HOURS=12\n' >> "$staging_root/odineyes.env"
grep -q '^ODINEYES_EBS_DIRECT_MAX_VOLUME_GIB=' "$staging_root/odineyes.env" || \
  printf 'ODINEYES_EBS_DIRECT_MAX_VOLUME_GIB=100\n' >> "$staging_root/odineyes.env"
grep -q '^ODINEYES_EBS_SNAPSHOT_WAIT_SECONDS=' "$staging_root/odineyes.env" || \
  printf 'ODINEYES_EBS_SNAPSHOT_WAIT_SECONDS=1800\n' >> "$staging_root/odineyes.env"
chown -R 10001:10001 "$staging_root/data"

docker stop odineyes-api odineyes-web odineyes-realtime || true
docker rename odineyes-api "$api_previous" || true
docker rename odineyes-web "$web_previous" || true
docker rename odineyes-realtime "$realtime_previous" || true
mv "$app_root" "$previous_root"
mv "$staging_root" "$app_root"
docker network create odineyes || true

rollback() {
  docker rm -f odineyes-api odineyes-web odineyes-realtime >/dev/null 2>&1 || true
  mv "$app_root" "$failed_root" || true
  mv "$previous_root" "$app_root"
  docker rename "$api_previous" odineyes-api >/dev/null 2>&1 || true
  docker rename "$web_previous" odineyes-web >/dev/null 2>&1 || true
  docker rename "$realtime_previous" odineyes-realtime >/dev/null 2>&1 || true
  docker start odineyes-api odineyes-web odineyes-realtime >/dev/null 2>&1 || true
}

docker run -d --name odineyes-api --restart unless-stopped --network odineyes \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=64m --tmpfs /home/odineyes:rw,noexec,nosuid,size=16m \
  --env-file "$app_root/odineyes.env" -v "$app_root/data:/var/lib/odineyes" \
  "$image_tag"
docker run -d --name odineyes-web --restart unless-stopped --network odineyes -p 80:80 \
  -v "$app_root/frontend/dist:/srv:ro" \
  -v "$app_root/deploy/aws/Caddyfile:/etc/caddy/Caddyfile:ro" \
  caddy:2.8-alpine
docker run -d --name odineyes-realtime --restart unless-stopped --network odineyes \
  --read-only --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --env-file "$app_root/odineyes.env" \
  --entrypoint /usr/local/bin/odineyes-realtime "$image_tag"

for _ in $(seq 1 30); do
  if docker exec odineyes-api python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health', timeout=2)" \
    && docker exec odineyes-api python -c "import urllib.request; urllib.request.urlopen('http://odineyes-realtime:8090/health', timeout=2)"; then
    docker rm "$api_previous" "$web_previous" "$realtime_previous" >/dev/null 2>&1 || true
    rm -rf "$previous_root" "$release_zip"
    echo "deployed ${release_name}"
    exit 0
  fi
  sleep 2
done

docker logs --tail 100 odineyes-api >&2 || true
rollback
echo "deployment failed; previous release restored" >&2
exit 1
