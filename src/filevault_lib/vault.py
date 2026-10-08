# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import logging
import shutil
from pathlib import Path

from filevault_lib.config import (
    ConfigManager,
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
)
from filevault_lib.exceptions import (
    InvalidVaultKey,
    InvalidVaultContainer,
    VaultNotCreatedError,
    VaultNotLoadedError,
    VaultNotOpenError,
    VaultNotClosedError,
    NonEmptyVaultError,
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
    add_object,
)

logger = logging.getLogger(__name__)


class Vault:                          # pylint: disable=too-many-public-methods
                                #  pylint: disable=too-many-instance-attributes
    def __init__(self, key: str, container: str | Path = None) -> None:
        if not key:
            raise InvalidVaultKey("Vault key cannot be null.")

        self._key = key
        self._uuid = None
        self._container = None
        self._root = None
        self._config = None

        if container:
            self._container = Path(container).resolve()
            self._uuid = get_vault_uuid(key, container)
            self._root = self._container / self._uuid


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
        if conf_file:
            self._config = load_config_for(self.get_key(), conf_file)

        self._config = self._config or ConfigManager()
        if conf:
            self._config.copy_form(
                conf,
                exclude=[
                    "KEY",
                    "CONTAINER",
                    "UUID"
                ]
            )

        self._config.set("KEY", self.get_key())

        try:
            self._container = Path(
                self._config.get("CONTAINER", self.get_container())
            ).resolve()
        except TypeError as exc:
            raise InvalidVaultContainer("Vault key cannot be null.") from exc

        self._uuid = get_vault_uuid(self.get_key(), self.get_container())
        self._root = self.get_container() / self.get_uuid()

        self._config.set("CONTAINER", self.get_container())
        self._config.set("UUID", self.get_uuid())


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
        flag = False

        if not self.is_created:
            # FIXME should return
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
            # FIXME should return
            raise VaultNotOpenError("Vault is not open.")

        with get_session_from(self._session_local) as session:
            set_status(session, "closed")

        self._db_engine.dispose()

        del self._db_engine
        del self._session_local


    def put(
        self,
        data: bytes | str,
        user_meta: dict = {},
        encrypt_algo: EncryptAlgo = EncryptAlgo.NONE,
        encrypt_key: str = None,
        compress_algo: CompressAlgo = CompressAlgo.NONE
    ) -> str:
        if isinstance(data, str):
            data = data.encode("utf-8")

        return add_object(
            compress(
                encrypt(data, encrypt_algo, encrypt_key),
                compress_algo
            ),
            user_meta,
            encrypt_algo,
            compress_algo
        )


    def get(
        self,
        key: str,
        decrypt: bool = True,
        decompress: bool = True
    ) -> (bytes, dict):
        pass


    def rm(
        self,
        key: str
    ) -> bool:
        pass

    def put1_d(self, file, meta: dict = None, compress=None, encrypt=None) -> str:
        pass


    def get_d(self, key: str):
        pass


    def put_s(self, stream, meta: dict = None) -> str:
        pass


    def get_s(self, key: str):
        pass


    def query(self):
        pass


    def sync(self):
        pass


    def export_to(self):
        pass


    def import_from(self):
        pass

