# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import logging
import uuid
import tomllib
from pathlib import Path

from typing import Any

from filevault_lib.exceptions import InvalidConfigFile


logger = logging.getLogger(__name__)


class Constants:                       # pylint: disable=too-few-public-methods
    NAMESPACE = uuid.UUID('01a0f944-aa5f-72e5-8bc0-25bf1f7d4b78')
    MAX_SHARD_SIZE = 1024 * 1024 * 1024  # Max shard size 1 GB, else create new
    MAX_FILE_SIZE_IN_SHARD = 20 * 1024 * 1024         # Filesize < 20MB goes to
                                                 #  shard, else individual file
    LOOSE_SHARD_SIZE = True      # if shard size is loosy, then shard available
                                 #  size slot is calculated from base file,
                                 #  else calculated from encrypted + compressed
                                 #  file which actually goes into shard, strict
                                 #  size increase operation time, as it needs
                                 #  final compressed + encrypted file to be
                                 #  exists before size caculation, so one write
                                 #  and one read time got added
    BULK_OP = 1024               # no of items to process at a time, if list is
                                 #  provided, as too much items can exceed sql
                                 #  params list, so this should not be too
                                 #  large. SQLite limit 32766 as max parameters
                                 #  to add in single query
    CHUNKS = 2 * 1024 * 1024                     # 2 MB chunk to read at a time
    # Performance-oriented Argon2id settings.
    ARGON_MEMORY_KIB = 8 * 1024                                     # 8 MiB
    ARGON_ITERATIONS = 1
    ARGON_LANES = 1
    ENCODING = "UTF-8"
    SYNC_ON_CLOSE = False         # sync the vault to perform error correction,
                                  # and other on-hold activities


class ConfigManager:
    def get(self, k: str, d: Any = None) -> Any:
        return getattr(self, k.upper(), d)

    def set(self, k: str, v: Any) -> None:
        setattr(self, k.upper(), v)

    def to_dict(self) -> dict:
        return {k: self.get(k) for k in dir(self) if k.isupper()}

    def unset(self, k: str) -> None:
        try:
            delattr(self, k.upper())
        except AttributeError:
            pass

    def from_dict(self, d: dict, exclude: list = None) -> None:
        if not d:
            return

        ex = [i.upper() for i in exclude or []]
        for k, v in d.items():
            if k.upper() not in ex:
                self.set(k, v)

    def copy_form(self, c: ConfigManager, exclude: list = None) -> None:
        if c:
            self.from_dict(c.to_dict(), exclude)


def load_config_for(key: str, file: Path | str) -> ConfigManager:
    file = Path(file).resolve()

    if not (file.exists()
        and file.is_file()
        and file.suffix in [".vault", ".toml"]
    ):
        raise InvalidConfigFile("Configuration file supplied is not valid.")

    with open(file, "rb") as f:
        _conf = tomllib.load(f) or {}

    conf = ConfigManager()
    for k, v in _conf.items():
        if k.upper() == key.upper():
            conf.from_dict(v)
            break

    return conf


def get_constants() -> dict:
    return {k: getattr(Constants, k) for k in dir(Constants) if k.isupper()}


def save_config_to(file: Path | str) -> None: # pylint: disable=unused-argument
    raise NotImplementedError

