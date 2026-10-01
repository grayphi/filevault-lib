# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import logging
import uuid
import tomllib

logger = logging.getLogger(__name__)


class Constants:
    NAMESPACE = uuid.UUID('01a0f944-aa5f-72e5-8bc0-25bf1f7d4b78')
    MAX_FILES_IN_DIR = 1000                     # Maximum files in a directory
    MAX_DIRS_IN_DIR = 1000                      # Maximum directory in a directory
    MAX_FILES_IN_DIR_IN_SHARDS = 1000           # Maximum files in a shard
    MAX_DIRS_IN_DIR_IN_SHARDS = 1000            # Maximum directory in a shard
    MAX_SHARD_SIZE = 1024 * 1024 * 1024         # Max shard size 1 GB, else create new
    MAX_FILE_SIZE_IN_SHARD = 20 * 1024 * 1024   # Filesize < 20MB goes to shard, else individual file



class ConfigManager:
    def get(self, k: str, d: Any = None) -> Any:
        return getattr(self, k.upper(), d)

    def set(self, k: str, v: Any):
        setattr(self, k.upper(), v)

    def to_dict(self) -> dict:
        return {k: self.get(k) for k in dir(self) if k.isupper()}

    def unset(self, k: str):
        try:
            delattr(self, k.upper())
        except AttributeError:
            pass



current_config = ConfigManager()


