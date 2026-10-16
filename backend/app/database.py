import re

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

_SCHEMA_RE = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")


def engine_connect_args(schema: str) -> dict:
    """asyncpg connect args that pin every connection to a single schema.
    An empty schema returns {} — i.e. exactly the previous behaviour. The name is
    validated because it ends up in a search_path setting."""
    if not schema:
        return {}
    if not _SCHEMA_RE.match(schema):
        raise ValueError(f"Invalid DATABASE_SCHEMA {schema!r}: use lowercase letters, digits and underscores")
    return {"server_settings": {"search_path": schema}}


engine = create_async_engine(
    settings.database_url, echo=False, pool_pre_ping=True, connect_args=engine_connect_args(settings.database_schema),
)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
