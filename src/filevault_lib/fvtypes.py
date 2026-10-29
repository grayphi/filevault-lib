# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import logging
from enum import Enum
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any, TypeAlias, TYPE_CHECKING

from pydantic import SecretStr

if TYPE_CHECKING:
    from filevault_lib.orm import (
        ObjectsTable,
        FilesTable,
        ShardsTable
    )


logger = logging.getLogger(__name__)


class KeyringRef(str, Enum):
    UNALLOTED = "U"
    OBJECT = "O"
    FILES = "F"
    SHARDS = "S"
    CACHE = "C"


class CompressAlgo(str, Enum):
    NONE = "none"
    DEFLATE = "zlib"                                          # DEFLATE == GZIP
    GZIP = "gzip"
    BZIP2 = "bz2"
    XZ = "xz"                                                      # XZ == LZMA
    LZMA = "lzma"


class EncryptAlgo(str, Enum):
    NONE = "none"
    AES_GCM = "aes-gcm"
    CHACHA20_POLY1305 = "chacha20-poly1305"

class BytesStream:                     # pylint: disable=too-few-public-methods
    def __init__(self, data: Iterable[bytes]):
        self._data: Iterator[bytes] = iter(data)
        self._buffer = bytearray()
        self._eof = False

    def read(self, size: int = -1) -> bytes:
        if size < 0:
            self._buffer.extend(b"".join(self._data))
            self._eof = True
            result = bytes(self._buffer)
            self._buffer.clear()
            return result

        while len(self._buffer) < size and not self._eof:
            try:
                self._buffer.extend(next(self._data))
            except StopIteration:
                self._eof = True

        result = bytes(self._buffer[:size])
        del self._buffer[:size]
        return result


VaultType: TypeAlias = "ObjectsTable | FilesTable | ShardsTable"

DataInItem: TypeAlias = str | bytes | Path | Iterable[bytes]
DataInType: TypeAlias = DataInItem | list[DataInItem]

DataOutType: TypeAlias = dict[
    str, tuple[
        None | Iterator[bytes], None | dict[str, Any]
    ]
]

PasskeyItem: TypeAlias = str | bytes | SecretStr
PasskeyType: TypeAlias = PasskeyItem | list[PasskeyItem]

CompressAlgoType: TypeAlias = str | CompressAlgo | list[CompressAlgo]
EncryptAlgoType: TypeAlias = str | EncryptAlgo | list[EncryptAlgo]


