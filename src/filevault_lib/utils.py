# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import logging
from uuid import UUID, uuid5
from pathlib import Path
from enum import Enum
from collections.abc import Iterator
import secrets
import string
import random
from functools import lru_cache
import zlib
import bz2
import lzma

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
    DEFLATE = "zlib"                                          # DEFLATE == GZIP
    GZIP = "gzip"
    BZIP2 = "bz2"
    XZ = "xz"                                                      # XZ == LZMA
    LZMA = "lzma"


class EncryptAlgo(str, Enum):
    NONE = "none"


def compress(
    data: bytes | str | Path,
    algo: CompressAlgo,
    stream: bool = False,
    chunk: int = Constants.CHUNKS
) -> bytes | Iterator[bytes]:
    if chunk <= 0:
        raise ValueError("chunk must be greater than zero")

    def read_chunks() -> Iterator[bytes]:
        if isinstance(data, Path):
            with data.open("rb") as file:
                while part := file.read(chunk):
                    yield part
        else:
            raw = data.encode("utf-8") if isinstance(data, str) else data
            for i in range(0, len(raw), chunk):
                yield raw[i:i + chunk]

    def compressed_chunks() -> Iterator[bytes]:
        if algo == CompressAlgo.NONE:
            yield from read_chunks()
            return

        if algo in (CompressAlgo.GZIP, CompressAlgo.DEFLATE):
            obj = zlib.compressobj(
                wbits=31 if algo == CompressAlgo.GZIP else zlib.MAX_WBITS
            )
        elif algo == CompressAlgo.BZIP2:
            obj = bz2.BZ2Compressor()
        elif algo in (CompressAlgo.LZMA, CompressAlgo.XZ):
            obj = lzma.LZMACompressor(
                format=lzma.FORMAT_XZ if algo == CompressAlgo.XZ
                else lzma.FORMAT_ALONE
            )
        else:
            raise ValueError(f"Unsupported compression algorithm: {algo}")

        for part in read_chunks():
            result = obj.compress(part)
            if result:
                yield result

        result = obj.flush()
        if result:
            yield result

    chunks = compressed_chunks()
    return chunks if stream else b"".join(chunks)


def decompress(
    data: bytes | Path,
    algo: CompressAlgo,
    stream: bool = False,
    chunk: int = Constants.CHUNKS
) -> bytes | Iterator[bytes]:
    if chunk <= 0:
        raise ValueError("chunk must be greater than zero")

    def read_chunks() -> Iterator[bytes]:
        if isinstance(data, Path):
            with data.open("rb") as file:
                while part := file.read(chunk):
                    yield part
        else:
            for i in range(0, len(data), chunk):
                yield data[i:i + chunk]

    def decompressed_chunks() -> Iterator[bytes]:
        if algo == CompressAlgo.NONE:
            yield from read_chunks()
            return

        if algo in (CompressAlgo.DEFLATE, CompressAlgo.GZIP):
            obj = zlib.decompressobj(
                wbits=31 if algo == CompressAlgo.GZIP else zlib.MAX_WBITS
            )
        elif algo == CompressAlgo.BZIP2:
            obj = bz2.BZ2Decompressor()
        elif algo in (CompressAlgo.XZ, CompressAlgo.LZMA):
            obj = lzma.LZMADecompressor(
                format=lzma.FORMAT_XZ if algo == CompressAlgo.XZ
                else lzma.FORMAT_ALONE
            )
        else:
            raise ValueError(f"Unsupported decompression algorithm: {algo}")

        for part in read_chunks():
            while True:
                if algo in (CompressAlgo.DEFLATE, CompressAlgo.GZIP):
                    result = obj.decompress(part, chunk)
                    needs_input = not obj.unconsumed_tail
                else:
                    result = obj.decompress(part, max_length=chunk)
                    needs_input = obj.needs_input

                if result:
                    yield result

                if obj.eof or needs_input:
                    break

                part = b""

        if not obj.eof:
            raise EOFError("Incomplete compressed stream")

    result = decompressed_chunks()
    return result if stream else b"".join(result)


def encrypt(data: bytes | str | Path, algo: EncryptAlgo, key: str) -> bytes:
    return data


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

                                # pylint: disable=too-many-positional-arguments
def save_file_as(                          # pylint: disable=too-many-arguments
    file: Path,
    shard_size_limit: int,
    shard_filesize_limit: int,
    encrypt_algo: EncryptAlgo,
    encrypt_key: str,
    compress_algo: CompressAlgo,
    vault_uuid: str | UUID,
    files_root: Path,
    shards_root: Path,
    chunk: int = Constants.CHUNKS
) -> Path:
    #if file.stat().st_size > shard_filesize_limit:
    if file.stat().st_size > 0:
        fout = _transform_plain_file(
            file,
            vault_uuid=vault_uuid,
            root=files_root,
            create=True
        )

    with fout.open("wb") as _fout:
        for _c in compress(
            file,
            algo=compress_algo,
            stream=True,
            chunk=chunk
        ):
            _fout.write(_c)

    return fout

