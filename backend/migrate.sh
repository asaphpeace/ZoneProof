#!/bin/sh
set -e

# Release step: brings the database to the current schema, then exits.
# Run it once per release (a one-off task), not once per replica.

echo "Checking database state..."

HAS_ALEMBIC=$(python3 - << 'PYEOF'
import asyncio
from sqlalchemy import text

async def main():
    from app.database import engine
    async with engine.connect() as conn:
        row = (await conn.execute(
            text("SELECT to_regclass('public.alembic_version')")
        )).scalar()
    print("1" if row is not None else "0")

asyncio.run(main())
PYEOF
)

if [ "$HAS_ALEMBIC" = "1" ]; then
    echo "Existing database — running Alembic migrations..."
    alembic upgrade head
else
    echo "Fresh database — creating schema via create_all..."
    python3 - << 'PYEOF'
import asyncio

async def main():
    from app.database import engine, Base
    import app.models  # registers all model classes with Base.metadata
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    print("Schema created.")

asyncio.run(main())
PYEOF
    echo "Stamping Alembic to head..."
    alembic stamp head
fi

echo "Database is ready."
