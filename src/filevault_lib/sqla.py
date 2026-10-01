# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines

import logging
import functools
from functools import lru_cache

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base, Session

from filevault_lib.config import current_config
from filevault_lib.exceptions import InvalidVaultKey


logger = logging.getLogger(__name__)


@lru_cache
def get_engine(key: str):
    if not key:
        raise InvalidVaultKey("Vault key cannot be null.")

    return create_engine(
        ,
        echo=current_app.debug
    )

engine = get_engine()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()


def get_session():
    s = SessionLocal()

    try:
        with s.begin():
            yield s
    finally:
        try:
            s.close()
        except Exception:              # pylint: disable=broad-exception-caught
            pass


def create_schema():
    Base.metadata.create_all(bind=get_engine())


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

