# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines, too-many-lines


import os
import sys
import logging
import shutil
import json
import tarfile
import io
import time
from pathlib import Path
from uuid import UUID
from datetime import datetime
from collections.abc import Iterable
from itertools import repeat

from pydantic import SecretStr

from filevault_lib.config import (
    ConfigManager,
    get_constants,
    load_config_for,
    save_config_to,
)
from filevault_lib.fvtypes import (
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
    delete_entry_from_shard,
    filesize_in_shard,
    get_shard_file,
    save_stream,
    fetch_stream_properties,
    del_files,
    del_shard_files,
    reclaim_shard_space,
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
    remove_objects,
    add_file,
    add_shard_file,
    record_shard_dirty,
    get_files,
    get_shards_files,
    remove_files,
    remove_shard_files,
    get_zombie_and_orphan_files,
    get_zombie_and_orphan_shard_files,
    get_dirty_shards,
    exec_query,
    record_shard_clean,
)
from filevault_lib.querylang import Query


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
            logger.warning("vault was not properly closed")
            # TODO


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

        if self.get_config().get("SYNC_ON_CLOSE"):
            self.sync()

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


                       # pylint: disable=too-many-branches, too-many-statements
                           # pylint: disable=too-many-arguments,too-many-locals
    def put(                    # pylint: disable=too-many-positional-arguments
        self,
        data: DataInType,
        meta: dict | list[dict] = None,
        encrypt_algo: EncryptAlgoType = EncryptAlgo.NONE,
        encrypt_key: PasskeyType = None,
        compress_algo: CompressAlgoType = CompressAlgo.NONE,
        strict: bool = False
    ) -> str | list[str]:
        def _unpack_keys(kd: dict[int, str | None]) -> str | list[str | None]:
            kl = [v for _, v in sorted(kd.items())]

            return kl.pop(0) if len(kl) == 1 else kl

        if not self.is_open:
            raise VaultNotOpenError("Vault is not open.")

        if not data:
            raise InputInconsitentException("Missing input data.")

        if not isinstance(data, list):
            data = [data]

        data = [
            d.encode(self.get_config().get("ENCODING"))
            if isinstance(d, str) else d
            for d in data
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
        objs = []
        streams = []
        files = []
        keys = {}

        for idx, _ds in enumerate(
            zip(data, meta, encrypt_algo, encrypt_key, compress_algo)
        ):
            keys[idx] = None

            if isinstance(_ds[0], bytes):
                objs += [(idx, _ds)]
            elif isinstance(_ds[0], Iterable):
                streams += [(idx, _ds)]
            elif isinstance(_ds[0], Path):
                if not (_ds[0].exists() and _ds[0].is_file()):
                    raise FileNotFoundError(f"File not found: {_ds[0]}")

                if not os.access(_ds[0], os.R_OK):
                    raise PermissionError(f"File not readable: {_ds[0]}")

                files += [(idx, _ds)]
            else:
                raise InputInconsitentException("Invalid data provided.")

        objs_ = []

        while objs:
            idx, (d, m, ea, ek, ca) = objs.pop(0)
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
            objs_ += [(idx, (d, s, m, ea, ca))]

        try:
            with get_session_from(self._session_local) as session:
                keys.update(
                    dict(
                        add_objects(
                            session,
                            data=objs_,
                            enc_params=ep,
                            bulk_op=self.get_config().get("BULK_OP")
                        )
                    )
                )
        except Exception as e:         # pylint: disable=broad-exception-caught
            logger.exception(e)
            logger.error(
                "Can't save objects, something unexpected happen."
            )
            if strict:
                return _unpack_keys(keys)

        while files:
            idx, (df, um, ea, ek, ca) = files.pop(0)
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

            if t == KeyringRef.FILES:
                try:
                    with get_session_from(self._session_local) as session:
                        keys[idx] = add_file(
                            session,
                            file=df_,
                            disk_size=(
                                self.get_files_root() / df_
                            ).stat().st_size,
                            meta=um,
                            encrypt_algo=ea,
                            compress_algo=ca,
                            enc_params=ep,
                            **fm
                        )
                except Exception as e: # pylint: disable=broad-exception-caught
                    logger.exception(e)
                    logger.error(
                        "Can't save file, something unexpected happen."
                    )
                    try:
                        (self.get_files_root() /  df_).unlink(missing_ok=True)
                    except:                       # pylint: disable=bare-except
                        pass

                    if strict:
                        return _unpack_keys(keys)
            else:
                try:
                    with get_session_from(self._session_local) as session:
                        keys[idx] = add_shard_file(
                            session,
                            file=df_,
                            shard=df_s,
                            disk_size=filesize_in_shard(
                                self.get_shards_root() / df_s,
                                df_
                            ),
                            meta=um,
                            encrypt_algo=ea,
                            compress_algo=ca,
                            enc_params=ep,
                            **fm
                        )
                except Exception as e: # pylint: disable=broad-exception-caught
                    logger.exception(e)
                    logger.error(
                        "Can't save file, something unexpected happen."
                    )
                    delete_entry_from_shard(
                        self.get_shards_root() / df_s,
                        df_
                    )

                    with get_session_from(self._session_local) as session:
                        record_shard_dirty(session, shard=df_s)

                    if strict:
                        return _unpack_keys(keys)

        while streams:
            idx, (ds, um, ea, ek, ca) = streams.pop(0)
            sm = fetch_stream_properties(ds)

            t, df_, df_s = save_stream(
                stream=ds,
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
                chunk=self.get_config().get("CHUNKS"),
                **ep
            )

            if t == KeyringRef.FILES:
                try:
                    with get_session_from(self._session_local) as session:
                        keys[idx] = add_file(
                            session,
                            file=df_,
                            disk_size=(
                                self.get_files_root() / df_
                            ).stat().st_size,
                            meta=um,
                            encrypt_algo=ea,
                            compress_algo=ca,
                            enc_params=ep,
                            **sm
                        )
                except Exception as e: # pylint: disable=broad-exception-caught
                    logger.exception(e)
                    logger.error(
                        "Can't save file, something unexpected happen."
                    )
                    try:
                        (self.get_files_root() /  df_).unlink(missing_ok=True)
                    except:                       # pylint: disable=bare-except
                        pass

                    if strict:
                        return _unpack_keys(keys)
            else:
                try:
                    with get_session_from(self._session_local) as session:
                        keys[idx] = add_shard_file(
                            session,
                            file=df_,
                            shard=df_s,
                            disk_size=filesize_in_shard(
                                self.get_shards_root() / df_s,
                                df_
                            ),
                            meta=um,
                            encrypt_algo=ea,
                            compress_algo=ca,
                            enc_params=ep,
                            **sm
                        )
                except Exception as e: # pylint: disable=broad-exception-caught
                    logger.exception(e)
                    logger.error(
                        "Can't save file, something unexpected happen."
                    )
                    delete_entry_from_shard(
                        self.get_shards_root() / df_s,
                        df_
                    )

                    with get_session_from(self._session_local) as session:
                        record_shard_dirty(session, shard=df_s)

                    if strict:
                        return _unpack_keys(keys)

        return _unpack_keys(keys)


    def get(                                # pylint: disable=too-many-branches
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
                if k in key:
                    key.pop(k)

        with get_session_from(self._session_local) as session:
            data.update({
                k: (
                    decrypt(
                        data=decompress(
                            data=(self.get_files_root() / f),
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
                ) for k, f, m in get_files(
                    session,
                    keys=set(key.keys()),
                    bulk_op=self.get_config().get("BULK_OP")
                )
            })

            for k in data:
                if k in key:
                    key.pop(k)

        with get_session_from(self._session_local) as session:
            data.update({
                k: (
                    decrypt(
                        data=decompress(
                            data=(
                                get_shard_file(
                                    shard=(self.get_shards_root() / s),
                                    file=f,
                                    stream=True,
                                    chunk=self.get_config().get("CHUNKS")
                                )
                            ),
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
                ) for k, s, f, m in get_shards_files(
                    session,
                    keys=set(key.keys()),
                    bulk_op=self.get_config().get("BULK_OP")
                )
            })

            for k in data:
                if k in key:
                    key.pop(k)

            for k in key:
                logger.debug("Non-existent key <%s>.", k)
                data[k] = (None, None)

        return data


    def remove(
        self,
        keys: str | list[str] | set[str],
        strict: bool = False
    ) -> dict[str, bool]:
        if not self.is_open:
            raise VaultNotOpenError("Vault is not open.")

        if isinstance(keys, str):
            keys = {keys}

        keys = set(keys)
        status = dict(zip(keys, repeat(False)))

        with get_session_from(self._session_local) as session:
            try:
                keys_ = remove_objects(
                    session=session,
                    keys=keys,
                    bulk_op=self.get_config().get("BULK_OP")
                )
                status.update(
                    dict(
                        zip(
                            keys_,
                            repeat(True)
                        )
                    )
                )
                keys -= keys_
            except Exception as e:     # pylint: disable=broad-exception-caught
                logger.exception(e)
                logger.error(
                    "Can't remove objects, something unexpected happen."
                )
                if strict:
                    return status

        with get_session_from(self._session_local) as session:
            try:
                fkt_ = remove_files(
                    session=session,
                    keys=keys,
                    bulk_op=self.get_config().get("BULK_OP")
                )
                del_files(
                    files=[i for _, i in fkt_],
                    files_root=self.get_files_root()
                )
                status.update(
                    dict(
                        zip(
                            [i for i,_ in fkt_],
                            repeat(True)
                        )
                    )
                )
                keys -= {i for i, _ in fkt_}
            except Exception as e:     # pylint: disable=broad-exception-caught
                logger.exception(e)
                logger.error(
                    "Can't remove files, something unexpected happen."
                )
                if strict:
                    return status

        with get_session_from(self._session_local) as session:
            try:
                sfkt_ = remove_shard_files(
                    session=session,
                    keys=keys,
                    bulk_op=self.get_config().get("BULK_OP")
                )
                del_shard_files(
                    files=[(i, j) for _, i, j in sfkt_],
                    shards_root=self.get_shards_root()
                )
                for _, i, _ in sfkt_:
                    record_shard_dirty(
                        session=session,
                        shard=self.get_shards_root() / i
                    )
                status.update(
                    dict(
                        zip(
                            [i for i, _, _ in sfkt_],
                            repeat(True)
                        )
                    )
                )
                keys -= {i for i, _, _ in sfkt_}
            except Exception as e:     # pylint: disable=broad-exception-caught
                logger.exception(e)
                logger.error(
                    "Can't remove shard files, something unexpected happen."
                )
                if strict:
                    return status

        return status


    def sync(self):
        if not self.is_created:
            raise VaultNotCreatedError("Vault is not created yet.")

        if not self.is_open:
            raise VaultNotOpenError("Vault is not open.")

        logger.info("STARTS SYNCING...")
        logger.warning(
            "Do not close, or interrupt the process"
            ", syncing is in progress..."
        )

        with get_session_from(self._session_local) as session:
            zf, of = get_zombie_and_orphan_files(
                session=session,
                files_root=self.get_files_root(),
                bulk_op=self.get_config().get("BULK_OP")
            )

            logger.debug("Total of %d zombies file(s) found.", len(zf))
            logger.debug("Total of %d orphan file(s) found.", len(of))

            remove_files(
                session=session,
                keys=set(zf),
                bulk_op=self.get_config().get("BULK_OP")
            )

            del_files(
                files=list(of),
                files_root=self.get_files_root()
            )

        with get_session_from(self._session_local) as session:
            zf, of = get_zombie_and_orphan_shard_files(
                session=session,
                shards_root=self.get_shards_root(),
                bulk_op=self.get_config().get("BULK_OP")
            )

            logger.debug("Total of %d zombies shard file(s) found.", len(zf))
            logger.debug("Total of %d orphan shard file(s) found.", len(of))

            remove_shard_files(
                session=session,
                keys=set(zf),
                bulk_op=self.get_config().get("BULK_OP")
            )

            del_shard_files(
                files=list(of),
                shards_root=self.get_shards_root()
            )

            for s in set(i for i, _ in of):
                record_shard_dirty(
                    session=session,
                    shard=s
                )

        with get_session_from(self._session_local) as session:
            for ds in get_dirty_shards(session):
                flag = reclaim_shard_space(
                    shard=ds,
                    root=self.get_shards_root()
                )
                if flag:
                    record_shard_clean(session, ds)

        logger.info("ENDS SYNCING...")


    def export_vault(
        self,
        destination: str = "-"
    ) -> None:
        def write_archive(output) -> None:
            with tarfile.open(fileobj=output, mode="w|gz") as archive:
                d = self.get_config().to_dict()
                d["CONTAINER"] = d["CONTAINER"].as_posix()
                d["NAMESPACE"] = str(d["NAMESPACE"])

                config_data = json.dumps(d).encode()

                info = tarfile.TarInfo("config.json")
                info.size = len(config_data)
                info.mtime = time.time()

                archive.addfile(info, io.BytesIO(config_data))
                for name in ["files", "shards", "catalog.db"]:
                    path = self.get_root() / name
                    if path.exists():
                        archive.add(
                            path,
                            arcname=f"{self.get_uuid()}/{name}",
                            recursive=True
                        )

        if destination == "-":
            write_archive(sys.stdout.buffer)
        else:
            with open(destination, "wb") as output:
                write_archive(output)


    def import_vault(
        self,
        source: str = "-",
        container: str | Path | None = None,
    ) -> None:
        target = Path(container or self.get_container())
        target.mkdir(parents=True, exist_ok=True)

        close_stream = source != "-"
                                          # pylint: disable=consider-using-with
        input_stream = open(source, "rb") if close_stream else sys.stdin.buffer

        try:
            with tarfile.open(fileobj=input_stream, mode="r|gz") as archive:
                config_member = archive.next()
                if (config_member is None
                    or config_member.name != "config.json"
                ):
                    raise ValueError("Archive must begin with config.json")

                config_file = archive.extractfile(config_member)
                if config_file is None:
                    raise ValueError("Cannot read config.json")

                with config_file:
                    config = json.load(config_file)

                uuid = config.get("UUID")
                if not isinstance(uuid, str) or not uuid:
                    raise ValueError("Missing or invalid vault UUID in config")

                vault_root = target / uuid
                vault_root.mkdir(parents=True, exist_ok=True)

                for member in archive:
                    if member.name == "config.json":
                        continue

                    path = Path(member.name)
                    if (
                        path.is_absolute()
                        or ".." in path.parts
                        or not path.parts
                        or path.parts[0] != uuid
                    ):
                        raise ValueError(
                            f"Invalid archive member: {member.name}"
                        )

                    relative = path.relative_to(uuid)
                    if (
                        not relative.parts
                        or relative.parts[0] not in {
                            "files", "shards", "catalog.db"
                        }
                        or (
                            relative.parts[0] == "catalog.db"
                            and len(relative.parts) != 1
                        )
                    ):
                        raise ValueError(
                            f"Unexpected archive member: {member.name}"
                        )

                    archive.extract(member, target, filter="data")
        finally:
            if close_stream:
                input_stream.close()


    def query(self, query: Query) -> set[str]:
        if not self.is_created:
            raise VaultNotCreatedError("Vault is not created yet.")

        if not self.is_open:
            raise VaultNotOpenError("Vault is not open.")

        if not (query and isinstance(query, Query)):
            raise ValueError("Invalid Query provided.")

        with get_session_from(self._session_local) as session:
            keys = exec_query(
                session=session,
                query=query.to_sqla()
            )

        return set(keys)

    def shell(self):
        raise NotImplementedError

