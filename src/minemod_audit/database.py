from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any, TypeVar

from pydantic import BaseModel
from sqlalchemy import JSON, Column, MetaData, String, Table, create_engine, delete, insert, select
from sqlalchemy.engine import Engine

T = TypeVar("T", bound=BaseModel)

metadata = MetaData()

records = Table(
    "records",
    metadata,
    Column("kind", String(64), primary_key=True),
    Column("key", String(128), primary_key=True),
    Column("payload", JSON, nullable=False),
)


class DataStore:
    def __init__(self, database_path: Path) -> None:
        database_path.parent.mkdir(parents=True, exist_ok=True)
        self.engine: Engine = create_engine(f"sqlite:///{database_path}", future=True)
        metadata.create_all(self.engine)

    def replace_models(
        self,
        kind: str,
        items: Iterable[T],
        *,
        key: Callable[[T], str],
    ) -> None:
        payloads = [
            {"kind": kind, "key": key(item), "payload": item.model_dump(mode="json")}
            for item in items
        ]
        with self.engine.begin() as connection:
            connection.execute(delete(records).where(records.c.kind == kind))
            if payloads:
                connection.execute(insert(records), payloads)

    def append_models(
        self,
        kind: str,
        items: Iterable[T],
        *,
        key: Callable[[T], str],
    ) -> None:
        payloads = [
            {"kind": kind, "key": key(item), "payload": item.model_dump(mode="json")}
            for item in items
        ]
        with self.engine.begin() as connection:
            for payload in payloads:
                connection.execute(
                    delete(records).where(
                        (records.c.kind == payload["kind"]) & (records.c.key == payload["key"])
                    )
                )
            if payloads:
                connection.execute(insert(records), payloads)

    def load_models(self, kind: str, model: type[T]) -> list[T]:
        statement = select(records.c.payload).where(records.c.kind == kind).order_by(records.c.key)
        with self.engine.connect() as connection:
            rows = connection.execute(statement).all()
        return [model.model_validate(row.payload) for row in rows]

    def load_payloads(self, kind: str) -> list[dict[str, Any]]:
        statement = select(records.c.payload).where(records.c.kind == kind).order_by(records.c.key)
        with self.engine.connect() as connection:
            rows = connection.execute(statement).all()
        return [dict(row.payload) for row in rows]
