# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines
# pylint: disable=unused-variable


import logging
from dataclasses import dataclass

from sqlalchemy.orm import (
    Mapped,
    mapped_column
)
from sqlalchemy import (
    String,
    text,
    UniqueConstraint,
    Index,
)

from filevault_lib.sqla import Base


logger = logging.getLogger(__name__)


_TABLE_PREFIX_ = "__filevault_lib_"

@dataclass
class RuntimeContextTable(Base):
    __tablename__ = f"{_TABLE_PREFIX_}_RUNTIME_CONTEXT"

    key: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        primary_key=True
    )
    value: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        server_default=text("''")
    )

    __table_args__ = (
        UniqueConstraint(
            key,
            name=f"{__tablename__}_uc_01"
        ),
        Index(
            f"{__tablename__}_sc_idx_01",
            key
        )
    )

