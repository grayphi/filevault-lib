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


class Expr:
    lvalue: Any
    op: Any
    rvalue: Any

    def __init__(self, lvalue: Any, op: Any, rvalue: Any):
        self.lvalue=lvalue
        self.op=op
        self.rvalue=rvalue


    def compile(self, cls: type):
        if cls not in [ObjectsTable, FilesTable, ShardsTable]:
            raise TypeError("Invalid class provided.")

        if self.rvalue is None:
            raise ValueError("expected rvalue.")

        if self.op == "and":
            return sa_and(rv.compile(cls) for rv in self.rvalue)
        if self.op == "or":
            return sa_or(rv.compile(cls) for rv in self.rvalue)
        if self.op == "not":
            return sa_not(self.rvalue.compile(cls))

        if self.lvalue is None or not isinstance(self.lvalue, Column):
            raise ValueError("missing or invalid lvalue.")

        if self.op == "lt":
            return self.lvalue.compile(cls) < self.rvalue
        if self.op == "gt":
            return self.lvalue.compile(cls) > self.rvalue
        if self.op == "le":
            return self.lvalue.compile(cls) <= self.rvalue
        if self.op == "ge":
            return self.lvalue.compile(cls) >= self.rvalue
        if self.op == "eq":
            return self.lvalue.compile(cls) == self.rvalue
        if self.op == "ne":
            return self.lvalue.compile(cls) != self.rvalue
        if self.op == "in":
            return self.lvalue.compile(cls).in_(self.rvalue)
        if self.op == "not in":
            return self.lvalue.compile(cls).not_in(self.rvalue)
        if self.op == "like":
            return self.lvalue.compile(cls).like(self.rvalue)
        if self.op == "ilike":
            return self.lvalue.compile(cls).ilike(self.rvalue)
        if self.op == "between":
            return self.lvalue.compile(cls).between(*self.rvalue)
        if self.op == "is":
            return self.lvalue.compile(cls).is_(self.rvalue)
        if self.op == "is not":
            return self.lvalue.compile(cls).is_not(self.rvalue)
        if self.op == "startswith":
            return self.lvalue.compile(cls).startswith(self.rvalue)
        if self.op == "istartswith":
            return self.lvalue.compile(cls).istartswith(self.rvalue)
        if self.op == "not ilike":
            return self.lvalue.compile(cls).not_ilike(self.rvalue)
        if self.op == "not like":
            return self.lvalue.compile(cls).not_like(self.rvalue)
        if self.op == "icontains":
            return self.lvalue.compile(cls).icontains(self.rvalue)
        if self.op == "contains":
            return self.lvalue.compile(cls).contains(self.rvalue)
        if self.op == "endswith":
            return self.lvalue.compile(cls).endswith(self.rvalue)
        if self.op == "iendswith":
            return self.lvalue.compile(cls).iendswith(self.rvalue)

        raise ValueError(f"Unsupported operator: {self.op}")


class Column:
    _name: str

    # FIXME meta column
    def __init__(self, name: str):
        if not (name and isinstance(name, str)):
            raise ValueError("Column name must be a non-empty string")
        self._name = name

    def compile(self, cls: VaultType) -> str:
        if cls not in [ObjectsTable, FilesTable, ShardsTable]:
            raise TypeError("Invalid class provided.")

        if self._name not in cls.__table__.columns.keys():
            raise ValueError(f"Unknown column: {self._name}")

        return cls.__table__.columns.get(self._name)

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
    _type: Type = Type.ANY
    _condition: Expr | None = None

    def on(self, target: Type) -> Query:
        if not (target or isinstance(target, Type)):
            raise TypeError("target must be a Type value")
        self._type = target

        return self

    def where(self, condition: Expr) -> Query:
        if condition and not isinstance(condition, Expr):
            raise TypeError("where() requires an expression")
        self._condition = condition

        return self

    def to_sqla(self) -> SelectBase:
        stmts = []
        _stmts = []

        if self._type is Type.DATA or self._type is Type.ANY:
            _stmts += [{
                ObjectsTable: select(ObjectsTable.key)}
            ]

        if self._type is Type.FILES or self._type is Type.ANY:
            _stmts += [
                {FilesTable: select(FilesTable.key)},
                {ShardsTable: select(ShardsTable.key)}
            ]

        for _p in _stmts:
            for t, s in _p.items():
                stmts += [s]
                if self._condition:
                    self._condition.compile(t)


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

