# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import logging
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
    LargeBinary,
    DateTime,
    Text,
)
from sqlalchemy.orm import (
    Mapped,
    mapped_column
)
from sqlalchemy.sql import (
    func,
)

from filevault_lib.sqla import Base
from filevault_lib.utils import (
    generate_key,
)
from filevault_lib.types import (
    KeyringRef,
    CompressAlgo,
    EncryptAlgo,
)


logger = logging.getLogger(__name__)

_TABLE_PREFIX_ = "__FILEVAULT_LIB_"


class RuntimeContextTable(Base):       # pylint: disable=too-few-public-methods
    __tablename__ = f"{_TABLE_PREFIX_}_RUNTIME_CONTEXT"

    key: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        primary_key=True
    )
    value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default=text("")
    )


class KeyringTable(Base):              # pylint: disable=too-few-public-methods
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
    file_size: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text("0")
    )
    disk_size: Mapped[int] = mapped_column(
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
    enc_params: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        server_default="{}"
    )
    user_meta: Mapped[dict] = mapped_column(
        JSON,
        nullable=False,
        server_default="{}"
    )
    permission: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        server_default=text("33184")         # octal: 0o100640, str: -rw-r-----
    )
    ownership: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        server_default=":"
    )
    created_on: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()                # pylint: disable=not-callable
    )
    modified_on: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()                # pylint: disable=not-callable
    )
    last_accessed_on: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now()                # pylint: disable=not-callable
    )


class ObjectsTable(Base, FileAttrs):   # pylint: disable=too-few-public-methods
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


class FilesTable(Base, FileAttrs):     # pylint: disable=too-few-public-methods
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


class ShardsTable(Base, FileAttrs):    # pylint: disable=too-few-public-methods
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


class CacheTable(Base, FileAttrs):     # pylint: disable=too-few-public-methods
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

