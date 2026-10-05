# vim:ts=4:sw=4:cc=80:et:si:sta:ai:nu:nowrap:cul:sm:is:hls:pt=<F3>:noic
# pylint: disable=missing-module-docstring, missing-function-docstring
# pylint: disable=missing-class-docstring, trailing-newlines


import logging

logger = logging.getLogger(__name__)


class InvalidVaultKey(Exception):
    pass


class InvalidVaultContainer(Exception):
    pass


class InvalidConfigFile(Exception):
    pass


class VaultNotLoadedError(Exception):
    pass


class InvalidVaultDb(Exception):
    pass


class BaseNotDeclaredError(Exception):
    pass



