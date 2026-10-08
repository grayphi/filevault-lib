# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import logging
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy import (
    String,
    Integer,
    text,
    UniqueConstraint,
    Index,
    ForeignKey,
    JSON,
    Enum,
    Boolean,
    LargeBinary,
    DateTime,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column
)
from sqlalchemy.sql import (
    expression,
    func,
)

from filevault_lib.sqla import Base
from filevault_lib.utils import (
    KeyringRef,
    generate_key,
    CompressAlgo,
    EncryptAlgo,
)


logger = logging.getLogger(__name__)

_TABLE_PREFIX_ = "__FILEVAULT_LIB_"


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
        server_default=""
    )


@dataclass
class KeyringTable(Base):
    __tablename__ = f"{_TABLE_PREFIX_}_KEYRING"

    key: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        primary_key=True,
        default=generate_key
    )
    fwd_ref: Mapped[KeyringRef] = mapped_column(
        Enum(KeyringRef),
        nullable=False,
        server_default=KeyringRef.UNALLOTED.value
    )


class FileAttrs:                       # pylint: disable=too-few-public-methods
    name: Mapped[str] = mapped_column(
        String(256),
        nullable=False,
        server_default=""
    )
    size: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text("0")
    )
    encrypt_algo: Mapped[EncryptAlgo] = mapped_column(
        Enum(EncryptAlgo),
        nullable=False,
        server_default=EncryptAlgo.NONE.value
    )
    compress_algo: Mapped[CompressAlgo] = mapped_column(
        Enum(CompressAlgo),
        nullable=False,
        server_default=CompressAlgo.NONE.value
    )
    user_meta: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        server_default="{}"
    )
    permission: Mapped[str] = mapped_column(
        String(4),
        nullable=False,
        server_default=text("'640'")
    )
    ownership: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        server_default=":"
    )
    created_on: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )
    modified_on: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()
    )


@dataclass
class ObjectsTable(Base, FileAttrs):
    __tablename__ = f"{_TABLE_PREFIX_}_OBJECTS"

    key: Mapped[str] = mapped_column(
        String(128),
        ForeignKey(f"{KeyringTable.__tablename__}.key"),
        nullable=False,
        primary_key=True
    )
    data: Mapped[bytes] = mapped_column(
         LargeBinary(length=1024*1024*1), # 1 MB
         nullable=False
    )


@dataclass
class FilesTable(Base, FileAttrs):
    __tablename__ = f"{_TABLE_PREFIX_}_FILES"

    key: Mapped[str] = mapped_column(
        String(128),
        ForeignKey(f"{KeyringTable.__tablename__}.key"),
        nullable=False,
        primary_key=True
    )
    loc: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
        unique=True
    )

    __table_args__ = (
        Index(
            f"{__tablename__}_SC_IDX_01",
            loc
        ),
    )


@dataclass
class ShardsTable(Base, FileAttrs):
    __tablename__ = f"{_TABLE_PREFIX_}_SHARDS"

    key: Mapped[str] = mapped_column(
        String(128),
        ForeignKey(f"{KeyringTable.__tablename__}.key"),
        nullable=False,
        primary_key=True
    )
    shard: Mapped[str] = mapped_column(
        String(1024),
        nullable=False
    )
    loc: Mapped[str] = mapped_column(
        String(1024),
        nullable=False
    )

    __table_args__ = (
        UniqueConstraint(
            shard,
            loc,
            name=f"{__tablename__}_UC_01"
        ),
        Index(
            f"{__tablename__}_MC_IDX_01",
            shard,
            loc
        )
    )


@dataclass
class CacheTable(Base, FileAttrs):
    __tablename__ = f"{_TABLE_PREFIX_}_CACHE"

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        nullable=False,
        autoincrement='auto'

    )
    loc: Mapped[str] = mapped_column(
        String(1024),
        nullable=False,
        unique=True
    )

    __table_args__ = (
        Index(
            f"{__tablename__}_SC_IDX_01",
            loc
        ),
    )

