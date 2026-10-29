# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


from __future__ import annotations

import logging
from enum import Enum
from typing import Any, Iterable

from sqlalchemy import (
    select,
    union,
    SelectBase,
    and_ as sa_and,
    not_ as sa_not,
    or_ as sa_or,
    Column as SAColumn,
)

from filevault_lib.fvtypes import VaultType
from filevault_lib.orm import (
    ObjectsTable,
    FilesTable,
    ShardsTable
)


logger = logging.getLogger(__name__)


class Type(Enum):
    DATA = "data"
    FILES = "files"
    ANY = "any"


class Expr:                            # pylint: disable=too-few-public-methods
    lvalue: Any
    op: Any
    rvalue: Any

    def __init__(self, lvalue: Any, op: Any, rvalue: Any):
        self.lvalue=lvalue
        self.op=op
        self.rvalue=rvalue


                                   # pylint: disable=too-many-return-statements
                                            # pylint: disable=too-many-branches
    def compile(self, cls: type):
        if cls not in [ObjectsTable, FilesTable, ShardsTable]:
            raise TypeError("Invalid class provided.")

        if self.op == "and":
            return sa_and(*(rv.compile(cls) for rv in self.rvalue))
        if self.op == "or":
            return sa_or(*(rv.compile(cls) for rv in self.rvalue))
        if self.op == "not":
            return sa_not(self.rvalue.compile(cls))

        if self.lvalue is None or not isinstance(self.lvalue, Column):
            raise ValueError("missing or invalid lvalue.")

        column = self.lvalue.compile(cls)
        value = self.rvalue

        if self.op == "lt":
            return column < value
        if self.op == "gt":
            return column > value
        if self.op == "le":
            return column <= value
        if self.op == "ge":
            return column >= value
        if self.op == "eq":
            return column.is_(None) if value is None else column == value
        if self.op == "ne":
            return column.is_not(None) if value is None else column != value
        if self.op == "in":
            return column.in_(value)
        if self.op == "not in":
            return column.not_in(value)
        if self.op == "like":
            return column.like(value)
        if self.op == "ilike":
            return column.ilike(value)
        if self.op == "between":
            return column.between(*value)
        if self.op == "is":
            return column.is_(value)
        if self.op == "is not":
            return column.is_not(value)
        if self.op == "startswith":
            return column.startswith(value)
        if self.op == "istartswith":
            return column.istartswith(value)
        if self.op == "not ilike":
            return column.not_ilike(value)
        if self.op == "not like":
            return column.not_like(value)
        if self.op == "icontains":
            return column.icontains(value)
        if self.op == "contains":
            return column.contains(value)
        if self.op == "endswith":
            return column.endswith(value)
        if self.op == "iendswith":
            return column.iendswith(value)

        raise ValueError(f"Unsupported operator: {self.op}")


class Column:
    _name: str

    def __init__(self, name: str):
        if not (name and isinstance(name, str)):
            raise ValueError("Column name must be a non-empty string")
        self._name = name

    def compile(self, cls: VaultType) -> SAColumn:
        if cls not in [ObjectsTable, FilesTable, ShardsTable]:
            raise TypeError("Invalid class provided.")

        for jcol in ("meta.", "enc_params."):
            if self._name.startswith(jcol):
                path = self._name.removeprefix(jcol).split(".")
                if any(not part for part in path):
                    raise ValueError(f"Invalid JSON path: {self._name}")

                column = getattr(cls, jcol[:-1])
                for part in path:
                    column = column[part]

                return column

        if self._name not in cls.__table__.columns.keys():
            raise ValueError(f"Unknown column: {self._name}")

        return getattr(cls, self._name)

    def __lt__(self, value: Any) -> Expr:
        return Expr(self, "lt", value)

    def __gt__(self, value: Any) -> Expr:
        return Expr(self, "gt", value)

    def __le__(self, value: Any) -> Expr:
        return Expr(self, "le", value)

    def __ge__(self, value: Any) -> Expr:
        return Expr(self, "ge", value)

    def __eq__(self, value: Any) -> Expr:
        return Expr(self, "eq", value)

    def __ne__(self, value: Any) -> Expr:
        return Expr(self, "ne", value)

    def in_(self, values: Iterable[Any]) -> Expr:
        return Expr(self, "in", values)

    def not_in(self, values: Iterable[Any]) -> Expr:
        return Expr(self, "not in", values)

    def like(self, pattern: str) -> Expr:
        return Expr(self, "like", pattern)

    def ilike(self, pattern: str) -> Expr:
        return Expr(self, "ilike", pattern)

    def between(self, low: Any, high: Any) -> Expr:
        return Expr(self, "between", (low, high))

    def is_(self, value: Any) -> Expr:
        return Expr(self, "is", value)

    def is_not(self, value: Any) -> Expr:
        return Expr(self, "is not", value)

    def startswith(self, value: Any) -> Expr:
        return Expr(self, "startswith", value)

    def istartswith(self, value: Any) -> Expr:
        return Expr(self, "istartswith", value)

    def not_ilike(self, pattern: str) -> Expr:
        return Expr(self, "not ilike", pattern)

    def not_like(self, pattern: str) -> Expr:
        return Expr(self, "not like", pattern)

    def icontains(self, value: Any) -> Expr:
        return Expr(self, "icontains", value)

    def contains(self, value: Any) -> Expr:
        return Expr(self, "contains", value)

    def endswith(self, value: Any) -> Expr:
        return Expr(self, "endswith", value)

    def iendswith(self, value: Any) -> Expr:
        return Expr(self, "iendswith", value)


class Query:
    def __init__(self):
        self._type = Type.ANY
        self._condition = None

    def on(self, target: Type) -> Query:
        if not isinstance(target, Type):
            raise TypeError("target must be a Type value")
        self._type = target

        return self

    def where(self, condition: Expr) -> Query:
        if not isinstance(condition, Expr):
            raise TypeError("where() requires an expression")
        self._condition = condition

        return self

    def to_sqla(self) -> SelectBase:
        stmts = []

        if self._type is Type.DATA:
            models = (ObjectsTable,)
        elif self._type is Type.FILES:
            models = (FilesTable, ShardsTable)
        else:
            models = (ObjectsTable, FilesTable, ShardsTable)

        for m in models:
            stmts += [
                select(m.key).where(self._condition.compile(m))
                    if self._condition else select(m.key)
            ]

        return union(*stmts) if len(stmts) > 1 else stmts[0]


def and_(*expressions: Expr) -> Expr:
    if not all((e and isinstance(e, Expr)) for e in expressions):
        raise TypeError("expected Expr.")
    return Expr(None, "and", expressions)

def or_(*expressions: Expr) -> Expr:
    if not all((e and isinstance(e, Expr)) for e in expressions):
        raise TypeError("expected Expr.")
    return Expr(None, "or", expressions)


def not_(expression: Expr) -> Expr:
    if not (expression and isinstance(expression, Expr)):
        raise TypeError("expected Expr.")
    return Expr(None, "not", expression)


def col(name: str) -> Column:
    return Column(name)

