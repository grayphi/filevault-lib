# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import logging
import uuid
from pathlib import Path
from enum import Enum
import secrets
import string
import random
from functools import lru_cache

from filevault_lib.config import Constants


logger = logging.getLogger(__name__)


def get_vault_uuid(key: str, container: Path) -> str:
    return str(
        uuid.uuid5(Constants.NAMESPACE, Path(container / key).as_posix())
        if (key and container)
        else None
    )


def path2url(p: Path | str) -> str:
    return "sqlite:///" + Path(p).resolve().as_posix() if p else ""


class KeyringRef(str, Enum):
    UNALLOTED = "U"
    OBJECT = "O"
    FILES = "F"
    SHARDS = "S"
    CACHE = "C"


def generate_key():
    @lru_cache(maxsize=1)
    def u():
        _u = list(string.ascii_letters + string.digits)
        random.shuffle(_u)
        return _u

    return "".join(
        secrets.choice(u()) for _ in range(secrets.randbelow(123) + 6)
    )


class CompressAlgo(str, Enum):
    NONE = "none"


class EncryptAlgo(str, Enum):
    NONE = "none"



def compress(data: bytes | str, algo: CompressAlgo) -> bytes:
    return data


def decompress(data: bytes, algo: CompressAlgo) -> bytes:
    return data


def encrypt(data: bytes | str, algo: EncryptAlgo, key: str) -> bytes:
    return data


def decrypt(data: bytes, algo: EncryptAlgo, key: str) -> bytes:
    return data

