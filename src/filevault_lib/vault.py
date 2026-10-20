# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import os
import logging
import shutil
from pathlib import Path
from uuid import UUID
from datetime import datetime
from collections.abc import Iterator, Iterable
from typing import TypeAlias
from io import BytesIO
from itertools import repeat

from pydantic import SecretStr
from cryptography.exceptions import InvalidTag

from filevault_lib.config import (
    Constants,
    ConfigManager,
    get_constants,
    load_config_for,
    save_config_to,
)
from filevault_lib.types import (
    CompressAlgo,
    EncryptAlgo,
    DataInType,
    DataOutType,
    PasskeyType,
    CompressAlgoType,
    EncryptAlgoType,
    KeyringRef,
)
from filevault_lib.utils import (
    get_vault_uuid,
    compress,
    decompress,
    encrypt,
    decrypt,
    save_file,
)
from filevault_lib.exceptions import (
    InvalidVaultKey,
    InvalidVaultContainer,
    VaultNotCreatedError,
    VaultNotLoadedError,
    VaultNotOpenError,
    VaultNotClosedError,
    NonEmptyVaultError,
    InputInconsitentException,
    VaultDecryptionError,
)
from filevault_lib.sqla import (
    create_engine_on,
    get_session_local,
    create_schema_on,
    get_session_from,
)
from filevault_lib.db import (
    get_status,
    set_status,
    get_stats,
    get_objects,
    add_objects,
)


logger = logging.getLogger(__name__)


class Vault:                          # pylint: disable=too-many-public-methods
                                #  pylint: disable=too-many-instance-attributes
    def __init__(
        self,
        key: str,
        container: str | Path = None,
        namespace: str | UUID = None
    ) -> None:
        if not key:
            raise InvalidVaultKey("Vault key cannot be null.")

        self._key = key
        self._uuid = None
        self._container = None
        self._root = None
        self._config = ConfigManager()
        self._config.set("KEY", self._key)

        if namespace:
            namespace = UUID(str(namespace))
            self._config.set("NAMESPACE", namespace)

        if container:
            self._container = Path(container).resolve()
            self._uuid = get_vault_uuid(key, container, namespace)
            self._root = self._container / self._uuid
            self._config.set("UUID", self._uuid)
            self._config.set("CONTAINER", self._container)


    def get_container(self) -> Path:
        return self._container


    def get_uuid(self) -> str:
        return self._uuid


    def get_root(self) -> Path:
        return self._root


    def get_key(self) -> str:
        return self._key


    def get_files_root(self) -> Path:
        return self.get_root() / "files" if self.get_root() else None


    def get_shards_root(self) -> Path:
        return self.get_root() / "shards" if self.get_root() else None


    def get_cache_root(self) -> Path:
        return self.get_root() / "cache" if self.get_root() else None


    def get_catalog(self) -> Path:
        return self.get_root() / "catalog.db" if self.get_root() else None


    def get_config(self) -> ConfigManager:
        return self._config


    def load(
        self,
        conf_file: Path|str = None,
        conf: ConfigManager = None
    ) -> None:
        exc_list = ["KEY"]

        if self.get_container():
            exc_list += ["CONTAINER"]

        if self.get_uuid():
            exc_list += ["UUID"]

        if self.get_config().get("NAMESPACE"):
            exc_list += ["NAMESPACE"]

        self._config.from_dict(
            get_constants(),
            exclude=exc_list
        )

        if conf_file:
            self._config.copy_form(
                load_config_for(self.get_key(), conf_file),
                exclude=exc_list
            )

        if conf:
            self._config.copy_form(
                conf,
                exclude=exc_list
            )

        try:
            self._container = Path(self._config.get("CONTAINER")).resolve()
            self._config.set("CONTAINER", self.get_container())
        except TypeError as exc:
            raise InvalidVaultContainer("Vault key cannot be null.") from exc

        self._uuid = get_vault_uuid(
            self.get_key(),
            self.get_container(),
            self.get_config().get("NAMESPACE")
        )
        self._config.set("UUID", self.get_uuid())
        self._root = self.get_container() / self.get_uuid()


    def save(self, to_file: Path|str) -> None:
        save_config_to(to_file)


    def create(self) -> None:
        if self.get_root():
            for p in [
                self.get_root(),
                self.get_files_root(),
                self.get_shards_root(),
                self.get_cache_root(),
            ]:
                p.mkdir(parents=True, exist_ok=True)

            self.get_catalog().touch(exist_ok=True)
        else:
            raise VaultNotLoadedError(
                "Cannot create vault: configuration is not loaded."
            )


    @property
    def is_created(self) -> bool:
        return bool(
            self.get_root()
            and all(
                p.exists()
                and p.is_dir() for p in [
                    self.get_root(),
                    self.get_files_root(),
                    self.get_shards_root(),
                    self.get_cache_root(),
                ]
            ) and all(
                p.exists()
                and p.is_file() for p in [
                    self.get_catalog(),
                ]
            )
        )


    def delete(self, force: bool = False) -> bool:
        #TODO check for object data presence in sqlite db
        flag = False

        if not self.is_created:
            raise VaultNotCreatedError("Vault is not created yet.")

        if self.is_open:
            raise VaultNotClosedError("Cannot delete open vault.")

        if any(any(p.iterdir()) for p in [
            self.get_files_root(),
            self.get_shards_root(),
            self.get_cache_root()
        ]):
            if force:
                shutil.rmtree(self.get_root())
                flag = True
            else:
                logger.warning(
                    "Cannot delete a non-empty vault. Use "
                    "force=True if this is intentional."
                )
                raise NonEmptyVaultError(
                    "Cannot delete a non-empty vault. Use "
                    "force=True if this is intentional."
                )
        else:
            shutil.rmtree(self.get_root())
            flag = True

        if flag:
            self._uuid = None
            self._container = None
            self._root = None
            self._config = None

        return flag


    def _sqla(self) -> None:
                               # pylint: disable=attribute-defined-outside-init
        self._db_engine = create_engine_on(self.get_catalog())
                               # pylint: disable=attribute-defined-outside-init
        self._session_local = get_session_local(self._db_engine)

        create_schema_on(self._db_engine)


    def open(self) -> None:
        if not self.is_created:
            raise VaultNotCreatedError("Vault is not created yet.")

        if self.is_open:
            return

        self._sqla()

        with get_session_from(self._session_local) as session:
            status = get_status(session)

        if status is None or status == "closed":
            with get_session_from(self._session_local) as session:
                set_status(session, "open")
        else:
            logger.debug("vault was not properly closed")
            # FIXME


    @property
    def is_open(self) -> bool:
        flag = all(
            hasattr(self, attr) and attr is not None
            for attr in [
                "_db_engine",
                "_session_local",
            ]
        )
        if flag:
            with get_session_from(self._session_local) as session:
                status = get_status(session)
            flag = bool(status and status == "open")

        return flag


    def close(self) -> None:
        if not self.is_open:
            raise VaultNotOpenError("Vault is not open.")

        with get_session_from(self._session_local) as session:
            set_status(session, "closed")

        self._db_engine.dispose()

        del self._db_engine
        del self._session_local


    def stats(self) -> dict:
        if not self.is_open:
            raise VaultNotOpenError("Vault is not open.")

        with get_session_from(self._session_local) as session:
            return get_stats(session)


    def put(
        self,
        data: DataInType,
        meta: dict | list[dict] = None,
        encrypt_algo: EncryptAlgoType = EncryptAlgo.NONE,
        encrypt_key: PasskeyType = None,
        compress_algo: CompressAlgoType = CompressAlgo.NONE
    ) -> str | list[str]:
        if not self.is_open:
            raise VaultNotOpenError("Vault is not open.")

        if not data:
            raise InputInconsitentException("Missing input data.")

        if not isinstance(data, list):
            data = [data]

        data = [
            d.encode(self.get_config().get("ENCODING")) for d in data
        ]

        n_size = len(data)

        if meta and isinstance(meta, list):
            if n_size != len(meta):
                raise InputInconsitentException(
                    "Total number of meta provided in list "
                    "mismatches data list."
                )
        else:
            meta = repeat(meta)

        if encrypt_algo and isinstance(encrypt_algo, list):
            if n_size != len(encrypt_algo):
                raise InputInconsitentException(
                    "Total number of encrypt_algo provided in "
                    "list mismatches data list."
                )
        else:
            if isinstance(encrypt_algo, str):
                try:
                    encrypt_algo = EncryptAlgo(encrypt_algo.lower())
                except ValueError as ve:
                    raise InputInconsitentException(
                        "Encryption algo is either invalid, or not supported."
                    ) from ve
            encrypt_algo = repeat(encrypt_algo)

        if encrypt_key and isinstance(encrypt_key, list):
            if n_size != len(encrypt_key):
                raise InputInconsitentException(
                    "Total number of encrypt_key provided in "
                    "list mismatches data list."
                )

            encrypt_key = [
                SecretStr(_k) if isinstance(_k, (str, bytes)) else _k
                    for _k in encrypt_key
            ]
        else:
            if encrypt_key and isinstance(encrypt_key, (str, bytes)):
                encrypt_key = SecretStr(encrypt_key)

            encrypt_key = repeat(encrypt_key)

        if compress_algo and isinstance(compress_algo, list):
            if n_size != len(compress_algo):
                raise InputInconsitentException(
                    "Total number of compress_algo provided in "
                    "list mismatches data list."
                )
        else:
            if isinstance(compress_algo, str):
                try:
                    compress_algo = CompressAlgo(compress_algo.lower())
                except ValueError as ve:
                    raise InputInconsitentException(
                        "Compress algo is either invalid, or not supported."
                    ) from ve
            compress_algo = repeat(compress_algo)

        ep = {
            "argon_memory_kib": self.get_config().get("ARGON_MEMORY_KIB"),
            "argon_iterations": self.get_config().get("ARGON_ITERATIONS"),
            "argon_lanes": self.get_config().get("ARGON_LANES"),
        }
        o = []
        s = []
        f = []

        for idx, _ds in enumerate(
            zip(data, meta, encrypt_algo, encrypt_key, compress_algo)
        ):
            if isinstance(_ds[0], bytes):
                o += [(idx, _ds)]
            elif isinstance(_ds[0], Iterable):
                s += [(idx, _ds)]
            elif isinstance(_ds[0], Path):
                if not (_ds[0].exists() and _ds[0].is_file()):
                    raise FileNotFoundError(f"File not found: {_ds[0]}")

                if not os.access(_ds[0], os.R_OK):
                    raise PermissionError(f"File not readable: {_ds[0]}")

                f += [(idx, _ds)]
            else:
                raise InputInconsitentException("Invalid data provided.")

        keys = []

        with get_session_from(self._session_local) as session:
            o_ = []
            while o:
                idx, (d, m, ea, ek, ca) = o.pop(0)
                s = len(d)
                d = compress(
                        data=encrypt(
                        data=d,
                        algo=ea,
                        secret=ek,
                        stream=True,
                        chunk=self.get_config().get("CHUNKS"),
                        **ep
                    ),
                    algo=ca,
                    stream=True,
                    chunk=self.get_config().get("CHUNKS")
                )
                o_ += [(idx, (d, s, m, ea, ca))]

            keys += add_objects(
                session,
                data=o_,
                enc_params=ep,
                bulk_op=self.get_config().get("BULK_OP")
            )

        with get_session_from(self._session_local) as session:
            while f:
                idx, (df, um, ea, ek, ca) = f.pop(0)
                inf = df.stat()
                fm = {
                    "name": df.name,
                    "file_size": inf.st_size,
                    "permission": inf.st_mode,
                    "ownership": f"{inf.st_uid}:{inf.st_gid}",
                    "created_on": datetime.fromtimestamp(inf.st_ctime),
                    "modified_on": datetime.fromtimestamp(inf.st_mtime),
                    "last_accessed_on": datetime.fromtimestamp(inf.st_atime),
                }

                t, df_, df_s = save_file(
                    df,
                    shard_size_limit=self.get_config().get("MAX_SHARD_SIZE"),
                    shard_filesize_limit=self.get_config().get(
                        "MAX_FILE_SIZE_IN_SHARD"
                    ),
                    encrypt_algo=ea,
                    encrypt_key=ek,
                    compress_algo=ca,
                    vault_uuid=self.get_uuid(),
                    files_root=self.get_files_root(),
                    shards_root=self.get_shards_root(),
                    cache_root=self.get_cache_root(),
                    loose_shard_size=self.get_config().get("LOOSE_SHARD_SIZE"),
                    chunk=self.get_config().get("CHUNKS"),
                    **ep
                )

                try:
                    if t == KeyringRef.FILES:
                        k = add_file(
                            session,
                            file=df_.relative_to(self.get_files_root()),
                            disk_size=df_.stat().st_size,
                            user_meta=um,
                            encrypt_algo=ea,
                            compress_algo=ca,
                            enc_params=ep,
                            **fm
                        )
                    else:
                        k = add_shard_file(
                            session,
                            file=df_.relative_to(self.get_shards_root()),
                            shard=df_s.relative_to(self.get_shards_root()),
                            disk_size=df_.stat().st_size,
                            user_meta=um,
                            encrypt_algo=ea,
                            compress_algo=ca,
                            enc_params=ep,
                            **fm
                        )

                    keys += [(idx, k)]
                except Exception as e:
                    logger.exception(e)
                    logger.error(
                        "Can't save file, something unexpected happen."
                    )
# FIXME
#                    try:
#                        if df_.is_relative_to(self.get_root()):
#                            df_.unlink(missing_ok=True)
#                    except ValueError:
#                        pass
                    raise e

        keys.sort(key=lambda x: x[0])
        keys = [j for _, j in keys]

        return keys.pop(0) if len(keys) == 1 else keys


    def get(
        self,
        key: str | list[str] | set[str],
        decrypt_key: PasskeyType = None
    ) -> DataOutType:
        if not self.is_open:
            raise VaultNotOpenError("Vault is not open.")

        if not key:
            raise InputInconsitentException("Missing input key(s).")

        if not isinstance(key, (list, set)):
            key = [key]

        if decrypt_key and isinstance(decrypt_key, list):
            if len(key) != len(decrypt_key):
                raise InputInconsitentException(
                    "Total number of decrypt_key provided in "
                    "list mismatches keys list."
                )

            decrypt_key = [
                SecretStr(_k) if isinstance(_k, (str, bytes)) else _k
                    for _k in decrypt_key
            ]
        else:
            if decrypt_key and isinstance(decrypt_key, (str, bytes)):
                decrypt_key = SecretStr(decrypt_key)

            decrypt_key = repeat(decrypt_key)

        key = dict(zip(key, decrypt_key))
        data = {}

        with get_session_from(self._session_local) as session:
            data.update({
                k: (
                    decrypt(
                        data=decompress(
                            data=d,
                            algo=m.pop("compress_algo"),
                            stream=True,
                            chunk=self.get_config().get("CHUNKS")
                        ),
                        algo=m.pop("encrypt_algo"),
                        secret=key.get(k),
                        stream=True,
                        chunk=self.get_config().get("CHUNKS"),
                        **m.pop("enc_params")
                    ),
                    m
                ) for k, d, m in get_objects(
                    session,
                    keys=set(key.keys()),
                    bulk_op=self.get_config().get("BULK_OP")
                )
            })

            for k in data:
                key.pop(k)

            # -----

            for k in key:
                logger.debug("Non-existent key <%s>.", k)
                data[k] = (None, None)

        return data



#    def rm(
#        self,
#        key: str
#    ):
#        if not self.is_open:
#            raise VaultNotOpenError("Vault is not open.")
#
#        with get_session_from(self._session_local) as session:
#            del_object(session=session, key=key)


#    def mrm(
#        self,
#        keys: list[str]
#    ):
#        if not self.is_open:
#            raise VaultNotOpenError("Vault is not open.")
#
#        with get_session_from(self._session_local) as session:
#            del_objects(session=session, keys=keys)


#    def putf(
#        self,
#        file: Path,
#        user_meta: dict = None,
#        encrypt_algo: EncryptAlgo = EncryptAlgo.NONE,
#        encrypt_key: str | SecretStr = None,
#        compress_algo: CompressAlgo = CompressAlgo.NONE
#    ) -> str:
#        if not self.is_open:
#            raise VaultNotOpenError("Vault is not open.")
#
#        file = Path(file)
#
#        if not (file.exists() or file.is_file()):
#            raise FileNotFoundError(f"File not found: {file}")
#
#        if not os.access(file, os.R_OK):
#            raise PermissionError(f"File not readable: {file}")
#
#        encrypt_key = (SecretStr(encrypt_key) if isinstance(encrypt_key, str)
#            else encrypt_key)
#        info = file.stat()
#
#        meta = {
#            "name": file.name,
#            "file_size": info.st_size,
#            "permission": info.st_mode,
#            "ownership": f"{info.st_uid}:{info.st_gid}",
#            "created_on": datetime.fromtimestamp(info.st_ctime),
#            "modified_on": datetime.fromtimestamp(info.st_mtime),
#            "last_accessed_on": datetime.fromtimestamp(info.st_atime),
#        }
#        enc_params = {
#            "argon_memory_kib": self.get_config().get("ARGON_MEMORY_KIB"),
#            "argon_iterations": self.get_config().get("ARGON_ITERATIONS"),
#            "argon_lanes": self.get_config().get("ARGON_LANES"),
#        }
#
#        file = save_file_as(
#            file,
#            shard_size_limit=self.get_config().get("MAX_SHARD_SIZE"),
#            shard_filesize_limit=self.get_config().get(
#                "MAX_FILE_SIZE_IN_SHARD"
#            ),
#            encrypt_algo=encrypt_algo,
#            encrypt_key=encrypt_key,
#            compress_algo=compress_algo,
#            vault_uuid=self.get_uuid(),
#            files_root=self.get_files_root(),
#            shards_root=self.get_shards_root(),
#            cache_root=self.get_cache_root(),
#            loose_shard_size=self.get_config().get("LOOSE_SHARD_SIZE"),
#            chunk=self.get_config().get("CHUNKS"),
#            **enc_params
#        )
#
#        key = None
#        try:
#            with get_session_from(self._session_local) as session:
#                key = add_file(
#                    session=session,
#                    file=file.relative_to(self.get_root()),
#                    disk_size=file.stat().st_size,
#                    user_meta=user_meta,
#                    encrypt_algo=encrypt_algo,
#                    compress_algo=compress_algo,
#                    enc_params=enc_params,
#                    **meta
#                )
#        except Exception as e:
#            logger.exception(e)
#            logger.error("Can't save file, something unexpected happen.")
#
#            try:
#                if file.relative_to(self.get_root()):
#                    file.unlink(missing_ok=True)
#            except ValueError:
#                pass
#
#            raise e
#
#        return key


    def query(self):
        pass


    def sync(self):
        pass


    def export_to(self):
        pass


    def import_from(self):
        pass

