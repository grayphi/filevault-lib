# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


from __future__ import annotations

import logging
import sys
from math import ceil
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING
from itertools import islice
from collections.abc import Iterable
import json

from sqlalchemy import (
    select,
    update,
    delete,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import (
    func,
)

if TYPE_CHECKING:
    from filevault_lib.vault import Vault
from filevault_lib.sqla import Session, transactional
from filevault_lib.orm import (
    RuntimeContextTable,
    KeyringTable,
    ObjectsTable,
    FilesTable,
    ShardsTable,
)
from filevault_lib.types import (
    KeyringRef,
    CompressAlgo,
    EncryptAlgo,
)
from filevault_lib.exceptions import DBException


logger = logging.getLogger(__name__)


@transactional
def get_runtime_context_var(session: Session, key: str) -> str:
    stmt = select(
        RuntimeContextTable.value
    ).where(
        RuntimeContextTable.key == key
    )

    try:
        ctx_var_val = session.execute(stmt).scalar_one_or_none()
    except Exception as e:
        logger.exception(e)
        raise DBException(
            "Something unexpected happened, while fetching RuntimeContext."
        ) from e

    return ctx_var_val



@transactional
def set_runtime_context_var(
    session: Session,
    key: str,
    value: str
) -> bool:
    flag = False

    stmt = update(
        RuntimeContextTable
    ).where(
        RuntimeContextTable.key == key
    ).values(
        **{RuntimeContextTable.value.key: value}
    )

    try:
        rs = session.execute(stmt)
        flag = int(rs.rowcount) > 0
    except IntegrityError as e:
        logger.exception(e)
    except Exception as e:
        logger.exception(e)
        raise DBException(
            "Something unexpected happened, while updating RuntimeContext var."
        ) from e

    if not flag:
        logger.debug("Can't update value, trying creating new.")
        ctx_obj = RuntimeContextTable(key=key, value=value)
        try:
            session.add(ctx_obj)
            session.flush()
            flag = True
        except IntegrityError as e:
            logger.exception(e)
            raise e
        except Exception as e:
            logger.exception(e)
            raise DBException(
                "Something unexpected happened, while "
                "creating RuntimeContext var."
            ) from e

    return flag


@transactional
def delete_runtime_context_var(session: Session, key: str) -> bool:
    flag = False

    stmt = delete(
        RuntimeContextTable
    ).where(
        RuntimeContextTable.key == key
    )

    try:
        rs = session.execute(stmt)
        flag = int(rs.rowcount) > 0
    except IntegrityError as e:
        logger.exception(e)
    except Exception as e:
        logger.exception(e)
        raise DBException(
            "Something unexpected happened, while "
            "deleting RuntimeContext var."
        ) from e

    return flag


def get_status(session: Session) -> str:
    return get_runtime_context_var(session, "status")


def set_status(session: Session, status: str) -> bool:
    return set_runtime_context_var(session, "status", status)


@transactional
def get_stats(session: Session) -> dict:
    stmt = select(
        KeyringTable.fwd_ref,
        func.count().label("total")              # pylint: disable=not-callable
    ).group_by(
        KeyringTable.fwd_ref
    )

    try:
        count_stats = session.execute(stmt).all()
        return dict(count_stats)
    except Exception as e:
        logger.exception(e)
        raise DBException(
            "Something unexpected happened, while fetching stats."
        ) from e


@transactional
def _get_keyrings(
    session: Session,
    type_: KeyringRef,
    count: int
) -> list[KeyringTable]:
    keyrings = []

    while True:
        keyrings = [KeyringTable(fwd_ref=type_) for _ in range(count)]

        try:
            with session.begin_nested():
                session.add_all(keyrings)
                session.flush()
            break
        except IntegrityError:
            logger.debug("key collide, trying new")
            continue

    return keyrings


@transactional
def add_objects(
    session: Session,
    data: list[
        tuple[
            int, tuple[
                bytes | Iterable[bytes], int, dict, EncryptAlgo, CompressAlgo
            ]
        ]
    ],
    enc_params: dict,
    bulk_op: int
) -> list[(int, str)]:
    keys = []
    needed = len(data)

    for _ in range(ceil(needed / bulk_op)):
        keyrings = _get_keyrings(
            session,
            type_=KeyringRef.OBJECT,
            count=min(bulk_op, needed)
        )

        objs = []
        for _ in range(min(bulk_op, needed)):
            k = keyrings.pop(0)
            idx, (d, s, m, ea, ca) = data.pop(0)
            d = d if isinstance(d, bytes) else b"".join(d)

            objs += [ObjectsTable(
                key=k.key,
                data=d,
                file_size=s,
                disk_size=len(d),
                encrypt_algo=ea,
                compress_algo=ca,
                user_meta=m,
                enc_params=enc_params
            )]
            keys += [(idx, k.key)]

        session.add_all(objs)
        session.flush()

        needed = needed - bulk_op

    return keys


@transactional
def get_objects(
    session: Session,
    keys: set[str],
    bulk_op: int
) -> list[tuple[str, bytes, dict]]:
    it = iter(keys)
    data = []
    while kl := list(islice(it, bulk_op)):
        stmt = select(
            ObjectsTable
        ).where(
            ObjectsTable.key.in_(kl)
        )

        try:
            objs = session.execute(stmt).scalars().all()
        except Exception as e:
            logger.exception(e)
            raise DBException(
                "Something unexpected happened, while fetching Object(s)."
            ) from e

        data += [(
            obj.key,
            obj.data,
            {
                "file_size": obj.file_size,
                "disk_size": obj.disk_size,
                "meta": obj.user_meta,
                "encrypt_algo": obj.encrypt_algo,
                "compress_algo": obj.compress_algo,
                "created_on": obj.created_on,
                "modified_on": obj.modified_on,
                "enc_params": obj.enc_params
            }
        ) for obj in objs]

    return data


#@transactional
#def del_objects(
#    session: Session,
#    keys: list[str]
#):
#    stmt_1 = delete(
#        ObjectsTable
#    ).where(
#        ObjectsTable.key.in_(keys)
#    )
#
#    stmt_2 = delete(
#        KeyringTable
#    ).where(
#        KeyringTable.key.in_(keys)
#    )
#
#    try:
#        session.execute(stmt_1)
#        session.execute(stmt_2)
#        session.flush()
#    except IntegrityError as e:
#        logger.exception(e)
#        raise DBException(
#            "Can't delete data, integrity check failed."
#        ) from e
#    except Exception as e:
#        logger.exception(e)
#        raise DBException(
#            "Something unexpected happened, while deleting data."
#        ) from e


                                # pylint: disable=too-many-positional-arguments
@transactional
def add_file(             # pylint: disable=too-many-arguments, too-many-locals
    session: Session,
    file: Path,
    name: str,
    file_size: int,
    disk_size: int,
    user_meta: dict,
    encrypt_algo: EncryptAlgo,
    compress_algo: CompressAlgo,
    permission: str,
    ownership: str,
    created_on: datetime,
    modified_on: datetime,
    last_accessed_on: datetime,
    enc_params: dict
) -> str:
    k = _get_keyrings(session, type_=KeyringRef.FILES, count=1).pop(0)

    o = FilesTable(
        key=k.key,
        loc=file.as_posix(),
        name=name,
        file_size=file_size,
        disk_size=disk_size,
        encrypt_algo=encrypt_algo,
        compress_algo=compress_algo,
        user_meta=user_meta,
        permission=permission,
        ownership=ownership,
        created_on=created_on,
        modified_on=modified_on,
        last_accessed_on=last_accessed_on,
        enc_params=enc_params
    )

    session.add(o)
    session.flush()

    return k.key

                                # pylint: disable=too-many-positional-arguments
@transactional
def add_shard_file(       # pylint: disable=too-many-arguments, too-many-locals
    session: Session,
    file: Path,
    shard: Path,
    name: str,
    file_size: int,
    disk_size: int,
    user_meta: dict,
    encrypt_algo: EncryptAlgo,
    compress_algo: CompressAlgo,
    permission: str,
    ownership: str,
    created_on: datetime,
    modified_on: datetime,
    last_accessed_on: datetime,
    enc_params: dict
) -> str:
    k = _get_keyrings(session, type_=KeyringRef.SHARDS, count=1).pop(0)

    o = ShardsTable(
        key=k.key,
        loc=file.as_posix(),
        shard=shard.as_posix(),
        name=name,
        file_size=file_size,
        disk_size=disk_size,
        encrypt_algo=encrypt_algo,
        compress_algo=compress_algo,
        user_meta=user_meta,
        permission=permission,
        ownership=ownership,
        created_on=created_on,
        modified_on=modified_on,
        last_accessed_on=last_accessed_on,
        enc_params=enc_params
    )

    session.add(o)
    session.flush()

    return k.key


@transactional
def record_dirty_shard(
    session: Session,
    shard: Path
) -> None:
    if sys.version_info[:2] >= (3, 16):  # future version directly supports
        return                           #  file remove form zipfilem, so there
                                         #  will not be any dirty shard.

    ctx_key = "dirty_shards"
    shard = shard.as_posix()

    ds = get_runtime_context_var(session, key=ctx_key)
    ds = json.loads(ds) if ds else {}

    # update total number of files that needs to be removed from shard
    ds[shard] = ds.get(shard, 0) + 1
    ds = json.dumps(ds)

    set_runtime_context_var(
        session,
        key=ctx_key,
        value=ds
    )


@transactional
def get_files(
    session: Session,
    keys: set[str],
    bulk_op: int
) -> list[tuple[str, Path, dict]]:
    it = iter(keys)
    data = []
    while kl := list(islice(it, bulk_op)):
        stmt = select(
            FilesTable
        ).where(
            FilesTable.key.in_(kl)
        )

        try:
            objs = session.execute(stmt).scalars().all()
        except Exception as e:
            logger.exception(e)
            raise DBException(
                "Something unexpected happened, while fetching file(s)."
            ) from e

        data += [(
            obj.key,
            Path(obj.loc),
            {
                "name": obj.name,
                "file_size": obj.file_size,
                "disk_size": obj.disk_size,
                "meta": obj.user_meta,
                "encrypt_algo": obj.encrypt_algo,
                "compress_algo": obj.compress_algo,
                "created_on": obj.created_on,
                "modified_on": obj.modified_on,
                "last_accessed_on": obj.last_accessed_on,
                "enc_params": obj.enc_params,
                "permission": obj.permission,
                "ownership": obj.ownership
            }
        ) for obj in objs]

    return data


@transactional
def get_shards_files(
    session: Session,
    keys: set[str],
    bulk_op: int
) -> list[tuple[str, Path, Path, dict]]:
    it = iter(keys)
    data = []
    while kl := list(islice(it, bulk_op)):
        stmt = select(
            ShardsTable
        ).where(
            ShardsTable.key.in_(kl)
        )

        try:
            objs = session.execute(stmt).scalars().all()
        except Exception as e:
            logger.exception(e)
            raise DBException(
                "Something unexpected happened, while fetching "
                "shard(s)'s file(s)."
            ) from e

        data += [(
            obj.key,
            Path(obj.shard),
            Path(obj.loc),
            {
                "name": obj.name,
                "file_size": obj.file_size,
                "disk_size": obj.disk_size,
                "meta": obj.user_meta,
                "encrypt_algo": obj.encrypt_algo,
                "compress_algo": obj.compress_algo,
                "created_on": obj.created_on,
                "modified_on": obj.modified_on,
                "last_accessed_on": obj.last_accessed_on,
                "enc_params": obj.enc_params,
                "permission": obj.permission,
                "ownership": obj.ownership
            }
        ) for obj in objs]

    return data


