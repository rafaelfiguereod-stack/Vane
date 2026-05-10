#!/bin/sh
set -e

# Generate or use provided SEARXNG_SECRET, then substitute into settings.yml
SETTINGS_PATH='/etc/searxng/settings.yml'
if [ -z "${SEARXNG_SECRET}" ]; then
  SEARXNG_SECRET="$(openssl rand -hex 32)"
  echo "Generated SEARXNG_SECRET (none provided via env)"
fi

# Write settings.yml with the real secret (copy from template if needed)
if [ ! -f "${SETTINGS_PATH}" ]; then
  cp /usr/local/searxng/searxng-src/searxng/settings.yml "${SETTINGS_PATH}" 2>/dev/null || true
fi

sed -i "s/REPLACE_WITH_SEARXNG_SECRET_AT_STARTUP/${SEARXNG_SECRET}/" "${SETTINGS_PATH}"

echo "Starting SearXNG..."

sudo -H -u searxng bash -c "cd /usr/local/searxng/searxng-src && export SEARXNG_SETTINGS_PATH='${SETTINGS_PATH}' && export FLASK_APP=searx/webapp.py && /usr/local/searxng/searx-pyenv/bin/python -m flask run --host=0.0.0.0 --port=8080" &
SEARXNG_PID=$!

echo "Waiting for SearXNG to be ready..."
sleep 5

COUNTER=0
MAX_TRIES=30
until curl -s http://localhost:8080 > /dev/null 2>&1; do
  COUNTER=$((COUNTER+1))
  if [ $COUNTER -ge $MAX_TRIES ]; then
    echo "Warning: SearXNG health check timeout, but continuing..."
    break
  fi
  sleep 1
done

if curl -s http://localhost:8080 > /dev/null 2>&1; then
  echo "SearXNG started successfully (PID: $SEARXNG_PID)"
else
  echo "SearXNG may not be fully ready, but continuing (PID: $SEARXNG_PID)"
fi

cd /home/vane
echo "Starting Vane..."

exec node server.js