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
    Integer
)

from filevault_lib.exceptions import BaseNotDeclaredError


logger = logging.getLogger(__name__)


class ORM:
    def __init__(self, base) -> None:
        self._Base = base                        # pylint: disable=invalid-name


    def init(self):
        if not self._Base:
            raise BaseNotDeclaredError("Invalid Base object.")

        self.declare_testclass()


    def declare_testclass(self):
        @dataclass
        class Testclass(self._Base):
            __tablename__ = "Testclass"

            uid: Mapped[int] = mapped_column(
                Integer,
                nullable=False,
                primary_key=True
            )


def create_orm(base) -> None:
    ORM(base).init()


