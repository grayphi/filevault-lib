# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import logging
import uuid
from pathlib import Path

from filevault_lib.config import Constants


logger = logging.getLogger(__name__)


def get_vault_uuid(key: str, container: Path) -> str:
    return str(
        uuid.uuid5(
            Constants.NAMESPACE,
            Path(container / key).as_posix()
        ) if (key and container) else None
    )
    
