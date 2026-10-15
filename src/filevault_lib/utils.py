# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import logging
from uuid import UUID, uuid5
from pathlib import Path
from enum import Enum
import secrets
import string
import random
from functools import lru_cache
import shutil

from filevault_lib.config import Constants


logger = logging.getLogger(__name__)


def get_vault_uuid(
    key: str,
    container: Path,
    namespace: str | UUID = None
) -> str:
    return str(
        uuid5(
            UUID(str(namespace)) if namespace else Constants.NAMESPACE,
            Path(container / key).as_posix()
        )
    ) if key and container else None


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



                                              # pylint: disable=unused-argument
def compress(data: bytes | str | Path, algo: CompressAlgo) -> bytes:
    return data


                                              # pylint: disable=unused-argument
def decompress(data: bytes, algo: CompressAlgo) -> bytes:
    return data


                                              # pylint: disable=unused-argument
def encrypt(data: bytes | str | Path, algo: EncryptAlgo, key: str) -> bytes:
    return data


                                              # pylint: disable=unused-argument
def decrypt(data: bytes, algo: EncryptAlgo, key: str) -> bytes:
    return data


def _transform_plain_file(
    file: Path,
    vault_uuid: str | UUID,
    root: Path = None,
    create: bool = True
) -> Path:
    _u = str(
        uuid5(
            UUID(str(vault_uuid)), str(
                {"filename": file.name, "size": file.stat().st_size}
            )
        )
    ).replace("-", "")
    _u = [_u[i:i+2] for i in range(0, len(_u), 2)]
    _u = _u[0:-6] + ["".join(_u[-6:])]

    p = Path()
    for i in _u:
        p = p / i

    p = Path(root) / p if root else p

    if root and create:
        p.parent.mkdir(parents=True, exist_ok=True)

    if not p.parent.exists():
        return p

    _f = [
        i.name.partition("-")[2]
        for i in Path(p.parent).iterdir() if i.name.startswith(p.name)
    ]

    try:
        _f.remove("")
    except ValueError:
        pass

    try:
        nxt = max(int(i, 16) for i in _f) + 1
    except ValueError:
        nxt = 0

    nxt = f"{nxt:02x}"
    nxt = nxt.zfill(len(nxt) + len(nxt) % 2)

    return Path(p.parent / f"{p.name}-{nxt}")


def save_file_as(
    file: Path,
    shard_size_limit: int,
    shard_filesize_limit: int,
    encrypt_algo: EncryptAlgo,
    encrypt_key: str,
    compress_algo: CompressAlgo,
    vault_uuid: str | UUID,
    files_root: Path,
    shards_root: Path
) -> Path:
    #if file.stat().st_size > shard_filesize_limit:
    if file.stat().st_size > 0:
        fout = _transform_plain_file(
            file,
            vault_uuid=vault_uuid,
            root=files_root
        )

        shutil.copyfile(file, fout)

    return fout

