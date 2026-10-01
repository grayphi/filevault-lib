# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import logging
import shutil
from pathlib import Path

from filevault_lib.utils import get_vault_uuid
from filevault_lib.exceptions import InvalidVaultKey, InvalidVaultContainer


logger = logging.getLogger(__name__)


class Vault:
    def __init__(self, key: str, container: str | Path) -> None:
        if not key:
            raise InvalidVaultKey("Vault key cannot be null.")
        if container:
            raise InvalidVaultContainer("Vault container cannot be null.")

        container = Path(container).resolve()
        self._root = container / get_vault_uuid(key, container)
        self._key = key


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


    def create(self) -> None:
        for p in [
            self.get_root(),
            self.get_files_root(),
            self.get_shards_root(),
            self.get_cache_root()
        ]:
            p.mkdir(parents=True, exist_ok=True)

        self.get_catalog().touch(exist_ok=True)


    @property
    def is_created(self) -> bool:
        return all(
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


    def delete(self, force=False) -> bool:
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
                    logger.warn("Cannot delete a non-empty vault. Use "
                    "force=True if this is intentional.")
            else:
                shutil.rmtree(self.get_root())
                flag = True
            
        return flag



