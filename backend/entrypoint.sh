#!/bin/sh
set -e

# ./entrypoint.sh migrate      run the release step only and exit (use as a one-off task)
# RUN_MIGRATIONS=false         start the API without touching the schema (replicas behind a load balancer)
# default                      migrate, then start, which keeps single-container compose working
if [ "$1" = "migrate" ]; then
    exec ./migrate.sh
fi

if [ "${RUN_MIGRATIONS:-true}" != "false" ]; then
    ./migrate.sh
else
    echo "RUN_MIGRATIONS=false: skipping schema step."
fi

echo "Starting Sentinel API..."
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
