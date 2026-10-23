from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from apps.server import models  # noqa: F401
from apps.server.db import Base, database_url

config = context.config
fileConfig(config.config_file_name)
target_metadata = Base.metadata


def run():
    configuration = config.get_section(config.config_ini_section)
    configuration["sqlalchemy.url"] = database_url()
    if context.is_offline_mode():
        context.configure(url=database_url(), target_metadata=target_metadata, literal_binds=True)
        with context.begin_transaction():
            context.run_migrations()
    else:
        engine = engine_from_config(configuration, prefix="sqlalchemy.", poolclass=pool.NullPool)
        with engine.connect() as connection:
            context.configure(connection=connection, target_metadata=target_metadata)
            with context.begin_transaction():
                context.run_migrations()


run()
