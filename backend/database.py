from __future__ import annotations

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

from .schema import SCHEMA_SQL


class Database:
    def __init__(self, connection_string: str, minimum: int = 2, maximum: int = 15):
        self.pool = ConnectionPool(
            conninfo=connection_string,
            min_size=minimum,
            max_size=maximum,
            kwargs={"row_factory": dict_row, "autocommit": False},
            open=False,
            timeout=30,
        )

    def open(self) -> None:
        self.pool.open(wait=True)
        with self.pool.connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute(SCHEMA_SQL)
            connection.commit()

    def close(self) -> None:
        self.pool.close()

    def health(self) -> dict:
        with self.pool.connection() as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT current_database() AS database, now() AS checked_at")
                return cursor.fetchone()
