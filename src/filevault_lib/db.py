# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import logging

from sqlalchemy import (
    select,
    update,
    delete,
)

from filevault_lib.sqla import Session, transactional
from filevault_lib.orm import RuntimeContextTable
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
        )

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
        )

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
            )

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
        )

    return flag


def get_status(session: Session) -> str:
    return get_runtime_context_var(session, "status")


def set_status(session: Session, status: str) -> bool:
    return set_runtime_context_var(session, "status", status)


