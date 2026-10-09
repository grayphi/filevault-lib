# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import logging

from sqlalchemy import (
    select,
    update,
    delete,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.sql import (
    func,
)

from filevault_lib.sqla import Session, transactional
from filevault_lib.orm import (
    RuntimeContextTable,
    KeyringTable,
    ObjectsTable,
    FilesTable,
    ShardsTable,
    CacheTable,
)
from filevault_lib.utils import (
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


            # pylint: disable=too-many-arguments, too-many-positional-arguments
@transactional
def add_object(
    session: Session,
    data: bytes,
    size: int,
    user_meta: dict,
    encrypt_algo: EncryptAlgo,
    compress_algo: CompressAlgo
) -> str:
    while True:
        k = KeyringTable(fwd_ref=KeyringRef.OBJECT)

        try:
            with session.begin_nested():
                session.add(k)
                session.flush()
            break
        except IntegrityError:
            logger.debug("key collide, trying new")
            continue

    o = ObjectsTable(                  # pylint: disable=unexpected-keyword-arg
        key=k.key,
        data=data,
        file_size=size,
        disk_size=len(data),
        encrypt_algo=encrypt_algo,
        compress_algo=compress_algo,
        user_meta=user_meta
    )

    session.add(o)
    session.flush()

    return k.key


@transactional
def get_object(
    session: Session,
    key: str
) -> (bytes, dict):
    stmt = select(
        ObjectsTable
    ).where(
        ObjectsTable.key == key
    )

    try:
        obj = session.execute(stmt).scalar_one_or_none()
    except Exception as e:
        logger.exception(e)
        raise DBException(
            "Something unexpected happened, while fetching Object."
        ) from e

    return (
        obj.data,
        {
            "file_size": obj.file_size,
            "disk_size": obj.disk_size,
            "user_meta": obj.user_meta,
            "encrypt_algo": obj.encrypt_algo,
            "compress_algo": obj.compress_algo,
            "created_on": obj.created_on,
            "modified_on": obj.modified_on
        }
    )


@transactional
def del_object(
    session: Session,
    key: str
):
    stmt_1 = delete(
        ObjectsTable
    ).where(
        ObjectsTable.key == key
    )

    stmt_2 = delete(
        KeyringTable
    ).where(
        KeyringTable.key == key
    )

    try:
        session.execute(stmt_1)
        session.execute(stmt_2)
        session.flush()
    except IntegrityError as e:
        logger.exception(e)
        raise DBException(
            "Can't delete data, integrity check failed."
        ) from e
    except Exception as e:
        logger.exception(e)
        raise DBException(
            "Something unexpected happened, while deleting data."
        ) from e


