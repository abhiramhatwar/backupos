import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Wire in all ORM models so autogenerate can see every table
from app.core.database import Base  # noqa: E402
import app.models.tenant  # noqa: F401, E402
import app.models.source  # noqa: F401, E402
import app.models.backup  # noqa: F401, E402
import app.models.policy  # noqa: F401, E402
import app.models.anomaly  # noqa: F401, E402
import app.models.audit  # noqa: F401, E402
import app.models.restore_job  # noqa: F401, E402

target_metadata = Base.metadata

# Allow DATABASE_URL env var to override alembic.ini
db_url = os.environ.get("DATABASE_URL", config.get_main_option("sqlalchemy.url"))
# Alembic uses sync psycopg2; strip asyncpg driver if present
sync_url = db_url.replace("+asyncpg", "") if db_url else db_url


def run_migrations_offline() -> None:
    context.configure(
        url=sync_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    cfg_section = config.get_section(config.config_ini_section, {})
    cfg_section["sqlalchemy.url"] = sync_url
    connectable = engine_from_config(cfg_section, prefix="sqlalchemy.", poolclass=pool.NullPool)
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
