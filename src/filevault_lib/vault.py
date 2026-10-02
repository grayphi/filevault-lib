# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import logging
import shutil
from pathlib import Path

from filevault_lib.config import (
    ConfigManager,
    load_config_for,
    save_config_to
)
from filevault_lib.utils import get_vault_uuid
from filevault_lib.exceptions import InvalidVaultKey, InvalidVaultContainer


logger = logging.getLogger(__name__)


class Vault:
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
        return self.get_root() / 'files'


    def get_shards_root(self) -> Path:
        return self.get_root() / 'shards'


    def get_cache_root(self) -> Path:
        return self.get_root() / 'cache'


    def get_catalog(self) -> Path:
        return self.get_root() / 'catalog.db'


    def get_config(self) -> ConfigManager:
        return self._config


    def create(self) -> None:
        if self.get_root():
            for p in [
                self.get_root(),
                self.get_files_root(),
                self.get_shards_root(),
                self.get_cache_root()
            ]:
                p.mkdir(parents=True, exist_ok=True)

            self.get_catalog().touch(exist_ok=True)

        # TODO create sqlite db strtucture


    @property
    def is_created(self) -> bool:
        return self.get_root() and all(
            p.exists() and p.is_dir() for p in [
                self.get_root(),
                self.get_files_root(),
                self.get_shards_root(),
                self.get_cache_root()
            ]
        ) and all(
            p.exists() and p.is_file for p in [
                self.get_catalog()
            ]
        )

        # TODO check if sqlite struturce exists

    def load(
        self,
        conf_file: Path|str = None,
        conf: ConfigManager = None
    ) -> None:
        if conf_file:
            self._config = load_config_for(self.get_key(), conf_file)

        if conf:
            self._config = self._config or ConfigManager()
            self._config.copy_form(
                conf,
                exclude=[
                    "KEY",
                    "CONTAINER",
                    "ROOT",
                    "UUID"
                ]
            )

        self._config = self._config or ConfigManager()
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
        self._config.set("ROOT", self.get_root())
        self._config.set("UUID", self.get_uuid())


    def delete(self, force: bool = False) -> bool:
        flag = False

        if self.is_created:
            if any(any(p.iterdir()) for p in [
                self.get_files_root(),
                self.get_shards_root(),
                self.get_cache_root()
            ]):
                if force:
                    shutil.rmtree(self.get_root())
                    flag = True
                else:
                    logger.warning("Cannot delete a non-empty vault. Use "
                    "force=True if this is intentional.")
            else:
                shutil.rmtree(self.get_root())
                flag = True

        return flag


    def save(self, to_file: Path|str) -> None:
        save_config_to(to_file)





