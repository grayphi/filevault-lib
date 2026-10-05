# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines

import logging
import functools
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session

from filevault_lib.utils import path2url
from filevault_lib.exceptions import InvalidVaultDb



logger = logging.getLogger(__name__)


def create_engine_on(loc: str|Path):
    if not loc:
        raise InvalidVaultDb("Invalid vault database location.")

    # FIXME: change echo=False later
    return create_engine(path2url(Path(loc).resolve()), echo=True)


def get_session_local(engine):
    return sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_base():
    return declarative_base()


def create_schema_on(base, engine):
    base.metadata.create_all(bind=engine)


def get_session_from(session_local):
    s = session_local()

    try:
        with s.begin():
            yield s
    finally:
        try:
            s.close()
        except Exception:              # pylint: disable=broad-exception-caught
            pass


def transactional(func):
    @functools.wraps(func)
    def wrapper(session: Session, *args, **kwargs):
        sp = session.begin_nested()
        try:
            result = func(session, *args, **kwargs)
            sp.commit()
            return result
        except Exception as e:
            logger.exception(e)
            logger.warning(
                "Changes in this transaction will not be persisted "
                "due to above exception."
            )
            sp.rollback()
            raise
    return wrapper


