# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import os
import logging
import shutil
from pathlib import Path
from uuid import UUID
from datetime import datetime

from filevault_lib.config import (
    ConfigManager,
    get_constants,
    load_config_for,
    save_config_to,
)
from filevault_lib.utils import (
    get_vault_uuid,
    CompressAlgo,
    EncryptAlgo,
    compress,
    decompress,
    encrypt,
    decrypt,
    save_file_as,
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
from filevault_lib import orm                   # pylint: disable=unused-import
from filevault_lib.db import (
    get_status,
    set_status,
    get_stats,
    add_object,
    get_object,
    del_object,
    get_objects,
    add_objects,
    del_objects,
    add_file,
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
        data: bytes | str,
        user_meta: dict = None,
        encrypt_algo: EncryptAlgo = EncryptAlgo.NONE,
        encrypt_key: str = None,
        compress_algo: CompressAlgo = CompressAlgo.NONE
    ) -> str:
        if not self.is_open:
            raise VaultNotOpenError("Vault is not open.")

        if isinstance(data, str):
            data = data.encode("utf-8")

        with get_session_from(self._session_local) as session:
            return add_object(
                session=session,
                data=compress(
                    data=encrypt(
                        data=data,
                        algo=encrypt_algo,
                        key=encrypt_key
                    ),
                    algo=compress_algo
                ),
                size=len(data),
                user_meta=user_meta,
                encrypt_algo=encrypt_algo,
                compress_algo=compress_algo
            )


    def get(
        self,
        key: str,
        decrypt_key: str = None
    ) -> (bytes, dict):
        if not self.is_open:
            raise VaultNotOpenError("Vault is not open.")

        with get_session_from(self._session_local) as session:
            data, meta = get_object(
                session=session,
                key=key
            )
            data = decompress(
                data=decrypt(
                    data=data,
                    algo=meta.pop("encrypt_algo"),
                    key=decrypt_key
                ),
                algo=meta.pop("compress_algo")
            ) if data else None
            return (data, meta)


    def rm(
        self,
        key: str
    ):
        if not self.is_open:
            raise VaultNotOpenError("Vault is not open.")

        with get_session_from(self._session_local) as session:
            del_object(session=session, key=key)


    # sqlite limit 32766 as max parameters to add in single query, so keys
    #  list should be less than that, create chunks of keys list and fetch
    #  in chunk, if more than that.
    def mget(
        self,
        keys: list[str],
        decrypt_keys: str | list[str] = None
    ) -> list[(str, bytes, dict)]:
        if not self.is_open:
            raise VaultNotOpenError("Vault is not open.")

        if decrypt_keys and isinstance(type(decrypt_keys), list):
            if len(decrypt_keys) != len(keys):
                logger.exception(
                    "Number of encrypt keys must match total "
                    "number of input keys."
                )
                raise InputInconsitentException(
                    "Number of encrypt keys must match total "
                    "number of input keys."
                )
        else:
            decrypt_keys = [decrypt_keys] * len(keys)

        with get_session_from(self._session_local) as session:
            objs = get_objects(
                session=session,
                keys=keys
            )
            objs = [(*o, k) for o, k in zip(objs, decrypt_keys)]
            objs = [(key,
                decompress(
                    data=decrypt(
                        data=data,
                        algo=meta.pop("encrypt_algo"),
                        key=decrypt_key
                    ),
                    algo=meta.pop("compress_algo")
                ), meta) for key, data, meta, decrypt_key in objs
            ]
            return objs

                                           # pylint: disable=too-many-arguments
                                # pylint: disable=too-many-positional-arguments
                                            # pylint: disable=too-many-branches
    def mput(
        self,
        datas: list[bytes | str],
        user_metas: dict | list[dict] = None,
        encrypt_algos: EncryptAlgo | list[EncryptAlgo] = None,
        encrypt_keys: str | list[str] = None,
        compress_algos: CompressAlgo | list[CompressAlgo] = None,
        chunk_size: int = 512
    ) -> list[str]:
        if not self.is_open:
            raise VaultNotOpenError("Vault is not open.")

        datas = [
            d.encode("utf-8") if isinstance(d, str) else d
            for d in datas
        ]
        l = len(datas)

        if user_metas and isinstance(type(user_metas), list):
            if l == len(user_metas):
                logger.exception(
                    "user_metas should be of same length as of data."
                )
                raise InputInconsitentException(
                    "user_metas should be of same length as of data."
                )
        else:
            user_metas = [user_metas] * l

        if encrypt_algos and isinstance(type(encrypt_algos), list):
            if l == len(encrypt_algos):
                logger.exception(
                    "encrypt_algos should be of same length as of data."
                )
                raise InputInconsitentException(
                    "encrypt_algos should be of same length as of data."
                )
        else:
            encrypt_algos = [
                encrypt_algos if isinstance(type(encrypt_algos), EncryptAlgo)
                else EncryptAlgo(str(encrypt_algos).lower())
            ] * l

        if encrypt_keys and isinstance(type(encrypt_keys), list):
            if l == len(encrypt_keys):
                logger.exception(
                    "encrypt_keys should be of same length as of data."
                )
                raise InputInconsitentException(
                    "encrypt_keys should be of same length as of data."
                )
        else:
            encrypt_keys = [encrypt_keys] * l

        if compress_algos and isinstance(type(compress_algos), list):
            if l == len(compress_algos):
                logger.exception(
                    "compress_algos should be of same length as of data."
                )
                raise InputInconsitentException(
                    "compress_algos should be of same length as of data."
                )
        else:
            compress_algos = [
                compress_algos if isinstance(
                    type(compress_algos), CompressAlgo
                ) else CompressAlgo(str(compress_algos).lower())
            ] * l

        datas = [
            (compress(
                data=encrypt(
                    data=d,
                    algo=ea,
                    key=ek
                ),
                algo=ca
            ), len(d)) for d, ea, ek, ca in zip(
                datas,
                encrypt_algos,
                encrypt_keys,
                compress_algos
            )
        ]

        datas, sizes = map(list, zip(*datas))
        with get_session_from(self._session_local) as session:
            return add_objects(
                session=session,
                datas=datas,
                sizes=sizes,
                user_metas=user_metas,
                encrypt_algos=encrypt_algos,
                compress_algos=compress_algos,
                chunk_size=chunk_size
            )


    def mrm(
        self,
        keys: list[str]
    ):
        if not self.is_open:
            raise VaultNotOpenError("Vault is not open.")

        with get_session_from(self._session_local) as session:
            del_objects(session=session, keys=keys)


    def putf(
        self,
        file: Path,
        user_meta: dict = None,
        encrypt_algo: EncryptAlgo = EncryptAlgo.NONE,
        encrypt_key: str = None,
        compress_algo: CompressAlgo = CompressAlgo.NONE
    ) -> str:
        if not self.is_open:
            raise VaultNotOpenError("Vault is not open.")

        file = Path(file)

        if not (file.exists() or file.is_file()):
            raise FileNotFoundError(f"File not found: {file}")

        if not os.access(file, os.R_OK):
            raise PermissionError(f"File not readable: {file}")

        info = file.stat()

        meta = {
            "name": file.name,
            "file_size": info.st_size,
            "permission": info.st_mode,
            "ownership": f"{info.st_uid}:{info.st_gid}",
            "created_on": datetime.fromtimestamp(info.st_ctime),
            "modified_on": datetime.fromtimestamp(info.st_mtime),
            "last_accessed_on": datetime.fromtimestamp(info.st_atime),
        }

        file = save_file_as(
            file,
            shard_size_limit=self.get_config().get("MAX_SHARD_SIZE"),
            shard_filesize_limit=self.get_config().get(
                "MAX_FILE_SIZE_IN_SHARD"
            ),
            encrypt_algo=encrypt_algo,
            encrypt_key=encrypt_key,
            compress_algo=compress_algo,
            vault_uuid=self.get_uuid(),
            files_root=self.get_files_root(),
            shards_root=self.get_shards_root()
        )

        key = None
        try:
            with get_session_from(self._session_local) as session:
                key = add_file(
                    session=session,
                    file=file.relative_to(self.get_root()),
                    disk_size=file.stat().st_size,
                    user_meta=user_meta,
                    encrypt_algo=encrypt_algo,
                    compress_algo=compress_algo,
                    **meta
                )
        except Exception as e:
            logger.exception(e)
            logger.error("Can't save file, something unexpected happen.")

            try:
                if file.relative_to(self.get_root()):
                    file.unlink(missing_ok=True)
            except ValueError:
                pass

            raise e

        return key


    def query(self):
        pass


    def sync(self):
        pass


    def export_to(self):
        pass


    def import_from(self):
        pass

