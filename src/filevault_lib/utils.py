# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines, too-many-lines


import os
import sys
import logging
from uuid import UUID, uuid5, uuid4
from pathlib import Path
from collections.abc import Iterable, Iterator
import secrets
import string
import random
from functools import lru_cache
import zlib
import bz2
import lzma
import struct
from io import BytesIO
from zipfile import ZIP_STORED, ZipFile

from pydantic import SecretStr
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from filevault_lib.config import Constants
from filevault_lib.fvtypes import (
    CompressAlgo,
    EncryptAlgo,
    BytesStream,
    KeyringRef
)


logger = logging.getLogger(__name__)


_MAGIC = b"FVENC001"
_HEADER_SIZE = 32
_TAG_SIZE = 16
_MAX_CHUNKS = 2**32 - 1


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


def generate_key():
    @lru_cache(maxsize=1)
    def u():
        _u = list(string.ascii_letters + string.digits)
        random.shuffle(_u)
        return _u

    return "".join(
        secrets.choice(u()) for _ in range(secrets.randbelow(123) + 6)
    )


def compress(
    data: bytes | str | Path | Iterable[bytes],
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
        elif isinstance(data, (str, bytes)):
            raw = data.encode("utf-8") if isinstance(data, str) else data
            for i in range(0, len(raw), chunk):
                yield raw[i:i + chunk]
        else:
            buffer = bytearray()
            for part in data:
                buffer.extend(part)
                while len(buffer) >= chunk:
                    yield bytes(buffer[:chunk])
                    del buffer[:chunk]
            if buffer:
                yield bytes(buffer)

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
    data: bytes | Path | Iterable[bytes],
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
        elif isinstance(data, bytes):
            for i in range(0, len(data), chunk):
                yield data[i:i + chunk]
        else:
            buffer = bytearray()
            for part in data:
                buffer.extend(part)
                while len(buffer) >= chunk:
                    yield bytes(buffer[:chunk])
                    del buffer[:chunk]
            if buffer:
                yield bytes(buffer)

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


def _derive_key(
    passkey: SecretStr,
    salt: bytes,
    argon_iterations: int = Constants.ARGON_ITERATIONS,
    argon_lanes: int = Constants.ARGON_LANES,
    argon_memory_kib: int = Constants.ARGON_MEMORY_KIB
) -> bytes:
    return Argon2id(
        salt=salt,
        length=32,
        iterations=argon_iterations,
        lanes=argon_lanes,
        memory_cost=argon_memory_kib,
    ).derive(passkey.get_secret_value().encode("utf-8"))


def _make_cipher(algo: EncryptAlgo, key: bytes):
    if algo == EncryptAlgo.AES_GCM:
        return AESGCM(key)

    if algo == EncryptAlgo.CHACHA20_POLY1305:
        return ChaCha20Poly1305(key)

    raise ValueError(f"Unsupported encryption algorithm: {algo}")


def _read_exact(source, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        part = source.read(size - len(result))
        if not part:
            raise EOFError("Incomplete encrypted stream")
        result.extend(part)
    return bytes(result)

                                # pylint: disable=too-many-positional-arguments
def encrypt(                               # pylint: disable=too-many-arguments
    data: bytes | str | Path | Iterable[bytes],
    algo: EncryptAlgo,
    secret: SecretStr,
    stream: bool = False,
    chunk: int = Constants.CHUNKS,
    argon_memory_kib: int = Constants.ARGON_MEMORY_KIB,
    argon_iterations: int = Constants.ARGON_ITERATIONS,
    argon_lanes: int = Constants.ARGON_LANES
) -> bytes | Iterator[bytes]:
    if chunk <= 0:
        raise ValueError("chunk must be greater than zero")

    def read_chunks() -> Iterator[bytes]:
        if isinstance(data, Path):
            with data.open("rb") as file:
                while part := file.read(chunk):
                    yield part
        elif isinstance(data, (str, bytes)):
            raw = data.encode("utf-8") if isinstance(data, str) else data
            for i in range(0, len(raw), chunk):
                yield raw[i:i + chunk]
        else:
            buffer = bytearray()
            for part in data:
                buffer.extend(part)
                while len(buffer) >= chunk:
                    yield bytes(buffer[:chunk])
                    del buffer[:chunk]
            if buffer:
                yield bytes(buffer)

    def encrypted_chunks() -> Iterator[bytes]:
        if not isinstance(algo, EncryptAlgo):
            raise ValueError(f"Unsupported encryption algorithm: {algo}")

        if algo == EncryptAlgo.NONE:
            yield from read_chunks()
            return

        if not (isinstance(secret, SecretStr) and secret.get_secret_value()):
            raise ValueError(
                "Passphrase is required for encryption,"
                " and in correct type."
            )

        salt = os.urandom(16)
        nonce_prefix = os.urandom(8)
        header = _MAGIC + salt + nonce_prefix
        cipher = _make_cipher(algo, _derive_key(
            passkey=secret,
            salt=salt,
            argon_iterations=argon_iterations,
            argon_lanes=argon_lanes,
            argon_memory_kib=argon_memory_kib
        ))
        yield header

        counter = 0
        for part in read_chunks():
            if counter >= _MAX_CHUNKS:
                raise ValueError("Maximum encrypted chunk count exceeded")

            nonce = nonce_prefix + struct.pack(">I", counter)
            aad = header + struct.pack(">I", counter) + b"\x00"
            ciphertext = cipher.encrypt(nonce, part, aad)

            yield b"\x00" + struct.pack(">I", len(ciphertext)) + ciphertext
            counter += 1

        nonce = nonce_prefix + struct.pack(">I", counter)
        aad = header + struct.pack(">I", counter) + b"\x01"
        final_record = cipher.encrypt(nonce, b"", aad)
        yield b"\x01" + struct.pack(">I", len(final_record)) + final_record

    result = encrypted_chunks()
    return result if stream else b"".join(result)

                                              # pylint: disable=too-many-locals
                                # pylint: disable=too-many-positional-arguments
def decrypt(                               # pylint: disable=too-many-arguments
    data: bytes | Path | Iterable[bytes],
    algo: EncryptAlgo,
    secret: SecretStr,
    stream: bool = False,
    chunk: int = Constants.CHUNKS,
    argon_memory_kib: int = Constants.ARGON_MEMORY_KIB,
    argon_iterations: int = Constants.ARGON_ITERATIONS,
    argon_lanes: int = Constants.ARGON_LANES
) -> bytes | Iterator[bytes]:
    if chunk <= 0:
        raise ValueError("chunk must be greater than zero")

    def read_chunks(source) -> Iterator[bytes]:
        while part := source.read(chunk):
            yield part

                                            # pylint: disable=too-many-branches
    def decrypted_chunks(source) -> Iterator[bytes]:
        if not isinstance(algo, EncryptAlgo):
            raise ValueError(f"Unsupported encryption algorithm: {algo}")

        if algo == EncryptAlgo.NONE:
            yield from read_chunks(source)
            return

        if not (isinstance(secret, SecretStr) and secret.get_secret_value()):
            raise ValueError(
                "Passphrase is required for decryption,"
                " and in correct type."
            )

        header = _read_exact(source, _HEADER_SIZE)
        if header[:len(_MAGIC)] != _MAGIC:
            raise ValueError("Invalid encrypted file format")

        salt = header[8:24]
        nonce_prefix = header[24:32]
        cipher = _make_cipher(algo, _derive_key(
            passkey=secret,
            salt=salt,
            argon_iterations=argon_iterations,
            argon_lanes=argon_lanes,
            argon_memory_kib=argon_memory_kib
        ))
        counter = 0

        while True:
            record_type = _read_exact(source, 1)
            length = struct.unpack(">I", _read_exact(source, 4))[0]

            if record_type == b"\x00":
                if counter >= _MAX_CHUNKS:
                    raise ValueError("Maximum encrypted chunk count exceeded")
                if not _TAG_SIZE <= length <= chunk + _TAG_SIZE:
                    raise ValueError("Invalid encrypted chunk length")
            elif record_type == b"\x01":
                if length != _TAG_SIZE:
                    raise ValueError("Invalid final record length")
            else:
                raise ValueError("Invalid encrypted record type")

            ciphertext = _read_exact(source, length)
            nonce = nonce_prefix + struct.pack(">I", counter)
            aad = header + struct.pack(">I", counter) + record_type
            plaintext = cipher.decrypt(nonce, ciphertext, aad)

            if record_type == b"\x01":
                if plaintext:
                    raise ValueError("Invalid final record")
                if source.read(1):
                    raise ValueError("Unexpected trailing data")
                return

            if plaintext:
                yield plaintext
            counter += 1

    def output_chunks() -> Iterator[bytes]:
        if isinstance(data, Path):
            with data.open("rb") as source:
                yield from decrypted_chunks(source)
        elif isinstance(data, bytes):
            with BytesIO(data) as source:
                yield from decrypted_chunks(source)
        else:
            yield from decrypted_chunks(BytesStream(data))

    result = output_chunks()
    return result if stream else b"".join(result)


def _transform_file(
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
    ).replace("-", "") if file and isinstance(file, Path) else str(
        uuid5(
            UUID(str(vault_uuid)), str(
                {
                    "filename": "".join(
                        random.choices(
                            string.ascii_letters + string.digits + "_-",
                            k=17
                        )
                    ),
                    "size": "-"
                }
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


def _new_shard(
    vault_uuid: str | UUID,
    shards_root: Path,
    shard_size_limit: int,
    shard_filesize_limit: int,
    create: bool = True
) -> Path:
    _u = str(
        uuid5(
            UUID(vault_uuid),
            "%s-%s:%s/%s" % (         # pylint: disable=consider-using-f-string
                shards_root.name,
                len([s for s in shards_root.rglob("*") if s.is_file()]) + 1,
                shard_size_limit,
                shard_filesize_limit
            )
        )
    ).replace("-", "")
    _u = [_u[i:i+2] for i in range(0, len(_u), 2)]
    _u = _u[0:-8] + ["".join(_u[-8:])]

    p = Path(shards_root)
    for i in _u:
        p = p / i

    if shards_root and create:
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


def _get_available_shard(
    shards_root: Path,
    need_space: int,
    shard_size_limit: int,
) -> Path:
    for shard in [s for s in shards_root.rglob("*") if s.is_file()]:
        if shard_size_limit - shard.stat().st_size > need_space:
            return shard
    return None


def _save_to(                              # pylint: disable=too-many-arguments
    file: Path,
    encrypt_algo: EncryptAlgo,
    encrypt_key: SecretStr,
    compress_algo: CompressAlgo,
    vault_uuid: str | UUID,
    root: Path,
    argon_memory_kib: int,
    argon_iterations: int,
    argon_lanes: int,
    chunk: int
) -> Path:
    fout = _transform_file(
        file,
        vault_uuid=vault_uuid,
        root=root,
        create=True
    )

    with fout.open("wb") as _fout:
        for _chunk in compress(
            encrypt(
                file,
                algo=encrypt_algo,
                secret=encrypt_key,
                stream=True,
                chunk=chunk,
                argon_memory_kib=argon_memory_kib,
                argon_iterations=argon_iterations,
                argon_lanes=argon_lanes
            ),
            algo=compress_algo,
            stream=True,
            chunk=chunk
        ):
            _fout.write(_chunk)

    return fout.relative_to(root)


def _save_as_file(                         # pylint: disable=too-many-arguments
    file: Path,
    encrypt_algo: EncryptAlgo,
    encrypt_key: SecretStr,
    compress_algo: CompressAlgo,
    vault_uuid: str | UUID,
    files_root: Path,
    argon_memory_kib: int,
    argon_iterations: int,
    argon_lanes: int,
    chunk: int
) -> Path:
    return _save_to(
        file=file,
        encrypt_algo=encrypt_algo,
        encrypt_key=encrypt_key,
        compress_algo=compress_algo,
        vault_uuid=vault_uuid,
        root=files_root,
        argon_memory_kib=argon_memory_kib,
        argon_iterations=argon_iterations,
        argon_lanes=argon_lanes,
        chunk=chunk
    )


def _save_as_shard_file(                   # pylint: disable=too-many-arguments
    file: Path,
    shard: Path,
    encrypt_algo: EncryptAlgo,
    encrypt_key: SecretStr,
    compress_algo: CompressAlgo,
    vault_uuid: str | UUID,
    shards_root: Path,
    argon_memory_kib: int,
    argon_iterations: int,
    argon_lanes: int,
    chunk: int
) -> Path:
    frel = _transform_file(
        file,
        vault_uuid=vault_uuid,
        root=shards_root,
        create=False
    )

    frel = frel.relative_to(shards_root)

    n = 0
    if Path(shard).exists():
        with ZipFile(shard, mode="r") as archive:
            n = max((
                int(f.name.partition("-")[2] or 0)
                for name in archive.namelist()
                    if (f := Path(name)).parent == frel.parent
                    and f.name.partition("-")[0] == frel.name.partition("-")[0]
                ),
                default=0,
            )
    n = f"{n + 1:02d}"
                                      # pylint: disable=consider-using-f-string
    frel = frel.parent / ("%s-%s" % (frel.name.partition("-")[0], n))

    with ZipFile(shard, mode="a", compression=ZIP_STORED) as archive:
        with archive.open(
            frel.as_posix(),
            mode="w",
            force_zip64=True
        ) as archf:
            for _chunk in compress(
                encrypt(
                    file,
                    algo=encrypt_algo,
                    secret=encrypt_key,
                    stream=True,
                    chunk=chunk,
                    argon_memory_kib=argon_memory_kib,
                    argon_iterations=argon_iterations,
                    argon_lanes=argon_lanes
                ),
                algo=compress_algo,
                stream=True,
                chunk=chunk
            ):
                archf.write(_chunk)

    return frel


def _cache_file(                           # pylint: disable=too-many-arguments
    file: Path,
    encrypt_algo: EncryptAlgo,
    encrypt_key: SecretStr,
    compress_algo: CompressAlgo,
    vault_uuid: str | UUID,
    cache_root: Path,
    argon_memory_kib: int,
    argon_iterations: int,
    argon_lanes: int,
    chunk: int
) -> Path:
    return _save_to(
        file=file,
        encrypt_algo=encrypt_algo,
        encrypt_key=encrypt_key,
        compress_algo=compress_algo,
        vault_uuid=vault_uuid,
        root=cache_root,
        argon_memory_kib=argon_memory_kib,
        argon_iterations=argon_iterations,
        argon_lanes=argon_lanes,
        chunk=chunk
    )


def _move_to_file(
    cached_file: Path,
    cache_root: Path,
    files_root: Path
) -> Path:
    fp = files_root / cached_file.relative_to(cache_root)
    fp.parent.mkdir(parents=True, exist_ok=True)

    if fp.exists():
        _f = [
            i.name.partition("-")[2]
            for i in Path(fp.parent).iterdir() if i.name.startswith(fp.name)
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

        fp = fp.parent / f"{fp.name}-{nxt}"

    cached_file.replace(fp)

    return fp.relative_to(files_root)


def _move_to_shard(
    shard: Path,
    cached_file: Path,
    cache_root: Path
) -> Path:
    frel = cached_file.relative_to(cache_root)

    with ZipFile(shard, mode="a", compression=ZIP_STORED) as archive:
        archive.write(
            cached_file,
            arcname=frel.as_posix()
        )

    if (cached_file.exists()
        and cached_file.is_file()
        and cached_file.is_relative_to(cache_root)
    ):
        cached_file.unlink(missing_ok=True)

    return frel


def save_file(                             # pylint: disable=too-many-arguments
    file: Path,
    shard_size_limit: int,
    shard_filesize_limit: int,
    encrypt_algo: EncryptAlgo,
    encrypt_key: SecretStr,
    compress_algo: CompressAlgo,
    vault_uuid: str | UUID,
    files_root: Path,
    shards_root: Path,
    cache_root: Path,
    loose_shard_size: bool,
    chunk: int,
    argon_memory_kib: int,
    argon_iterations: int,
    argon_lanes: int
) -> tuple[KeyringRef, Path, Path | None]:
    fs_orig = file.stat().st_size
    type_ = None
    fp = None
    sp = None

    if loose_shard_size:
        if fs_orig <= shard_filesize_limit:
            type_ = KeyringRef.SHARDS
            sp = _get_available_shard(
                shards_root=shards_root,
                shard_size_limit=shard_size_limit,
                need_space=fs_orig
            ) or _new_shard(
                vault_uuid=vault_uuid,
                shards_root=shards_root,
                shard_size_limit=shard_size_limit,
                shard_filesize_limit=shard_filesize_limit,
                create=True
            )

            fp = _save_as_shard_file(
                file=file,
                shard=sp,
                encrypt_algo=encrypt_algo,
                encrypt_key=encrypt_key,
                compress_algo=compress_algo,
                vault_uuid=vault_uuid,
                shards_root=shards_root,
                argon_memory_kib=argon_memory_kib,
                argon_iterations=argon_iterations,
                argon_lanes=argon_lanes,
                chunk=chunk
            )

            sp = sp.relative_to(shards_root)
        else:
            type_ = KeyringRef.FILES
            fp = _save_as_file(
                file=file,
                encrypt_algo=encrypt_algo,
                encrypt_key=encrypt_key,
                compress_algo=compress_algo,
                vault_uuid=vault_uuid,
                files_root=files_root,
                argon_memory_kib=argon_memory_kib,
                argon_iterations=argon_iterations,
                argon_lanes=argon_lanes,
                chunk=chunk
            )
    else:
        fc = _cache_file(
            file=file,
            encrypt_algo=encrypt_algo,
            encrypt_key=encrypt_key,
            compress_algo=compress_algo,
            vault_uuid=vault_uuid,
            cache_root=cache_root,
            argon_memory_kib=argon_memory_kib,
            argon_iterations=argon_iterations,
            argon_lanes=argon_lanes,
            chunk=chunk
        )
        fc = cache_root / fc
        fc_size = fc.stat().st_size

        if fc_size <= shard_filesize_limit:
            type_ = KeyringRef.SHARDS
            sp = _get_available_shard(
                shards_root=shards_root,
                shard_size_limit=shard_size_limit,
                need_space=fc_size
            ) or _new_shard(
                vault_uuid=vault_uuid,
                shards_root=shards_root,
                shard_size_limit=shard_size_limit,
                shard_filesize_limit=shard_filesize_limit,
                create=True
            )

            fp = _move_to_shard(
                shard=sp,
                cached_file=fc,
                cache_root=cache_root
            )
            sp = sp.relative_to(shards_root)
        else:
            type_ = KeyringRef.FILES
            fp = _move_to_file(
                cached_file=fc,
                cache_root=cache_root,
                files_root=files_root
            )

    return (type_, fp, sp)


def is_file_in_shard(
    shard: Path,
    file: str | Path
) -> bool:
    file = file.as_posix() if isinstance(file, Path) else file

    if Path(shard).exists():
        with ZipFile(shard, mode="r") as zf:
            try:
                zf.getinfo(file)
                return True
            except KeyError:
                pass
    return False


def iter_shard_files(
    shard: Path
) -> Iterator[Path]:
    def _iter_shard() -> Iterator[Path]:
        with ZipFile(shard, "r") as zf:
            for info in zf.infolist():
                if not info.is_dir():
                    yield Path(info.filename)

    return _iter_shard()


def filesize_in_shard(
    shard: Path,
    file: str | Path
) -> int:
    file = file.as_posix() if isinstance(file, Path) else file

    with ZipFile(shard) as zf:
        info = zf.getinfo(file)
        return info.compress_size


def delete_entry_from_shard(
    shard: Path,
    file: str | Path
) -> None:
    file = file.as_posix() if isinstance(file, Path) else file

    if sys.version_info[:2] < (3, 16):
        with ZipFile(shard, mode="a") as zf:
            f = zf.NameToInfo.pop(file, None)

            if f:
                zf.filelist.remove(f)

            zf.mkdir(f"__temp__/{uuid4().hex}/")
    else:
        with ZipFile(shard, mode="a") as archive:
                                                    # pylint: disable=no-member
            removed = archive.remove(file)
            archive.repack([removed])


def get_shard_file(
    shard: Path,
    file: str | Path,
    stream: bool,
    chunk: int
) -> bytes | Iterable[bytes]:
    file = file.as_posix() if isinstance(file, Path) else file

    if not stream:
        with ZipFile(shard, "r") as archive:
            return archive.read(file)

    def iter_chunks() -> Iterable[bytes]:
        with ZipFile(shard, "r") as archive:
            with archive.open(file, "r") as member:
                while part := member.read(chunk):
                    yield part

    return iter_chunks()


def fetch_stream_properties(ds: Iterable[bytes]) -> dict:
    # TODO
    sm = {
        "name": None,
        "file_size": None,
        "permission": None,
        "ownership": None,
        "created_on": None,
        "modified_on": None,
        "last_accessed_on": None,
    }

    return sm


def save_stream(                           # pylint: disable=too-many-arguments
    stream: Iterable[bytes],
    shard_size_limit: int,
    shard_filesize_limit: int,
    encrypt_algo: EncryptAlgo,
    encrypt_key: SecretStr,
    compress_algo: CompressAlgo,
    vault_uuid: str | UUID,
    files_root: Path,
    shards_root: Path,
    cache_root: Path,
    chunk: int,
    argon_memory_kib: int,
    argon_iterations: int,
    argon_lanes: int
) -> tuple[KeyringRef, Path, Path | None]:
    fc = _transform_file(
        file=None,
        vault_uuid=vault_uuid,
        root=cache_root,
        create=True
    )

    with fc.open("wb") as _fc:
        for _chunk in compress(
            encrypt(
                stream,
                algo=encrypt_algo,
                secret=encrypt_key,
                stream=True,
                chunk=chunk,
                argon_memory_kib=argon_memory_kib,
                argon_iterations=argon_iterations,
                argon_lanes=argon_lanes
            ),
            algo=compress_algo,
            stream=True,
            chunk=chunk
        ):
            _fc.write(_chunk)

    fc_size = fc.stat().st_size

    type_ = None
    fp = None
    sp = None
    if fc_size <= shard_filesize_limit:
        type_ = KeyringRef.SHARDS
        sp = _get_available_shard(
            shards_root=shards_root,
            shard_size_limit=shard_size_limit,
            need_space=fc_size
        ) or _new_shard(
            vault_uuid=vault_uuid,
            shards_root=shards_root,
            shard_size_limit=shard_size_limit,
            shard_filesize_limit=shard_filesize_limit,
            create=True
        )

        fp = _move_to_shard(
            shard=sp,
            cached_file=fc,
            cache_root=cache_root
        )
        sp = sp.relative_to(shards_root)
    else:
        type_ = KeyringRef.FILES
        fp = _move_to_file(
            cached_file=fc,
            cache_root=cache_root,
            files_root=files_root
        )

    return (type_, fp, sp)


def del_files(
    files: list[Path],
    files_root: Path
) -> None:
    for f in files:
        df = files_root / f

        if df.exists() and df.is_file():
            df.unlink(missing_ok=True)


def del_shard_files(
    files: list[tuple[Path, Path]],
    shards_root: Path
) -> None:
    for s, f in files:
        s = shards_root / s
        delete_entry_from_shard(s, f)


def iter_files(root: Path) -> Iterator[Path]:
    for r, _, fl in os.walk(root):
        for f in fl:
            yield (Path(r) / f).relative_to(root)


