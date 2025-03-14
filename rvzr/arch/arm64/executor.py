"""
File: Implementation of executor for arm64 architecture

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from rvzr.executor import Executor
from rvzr.config import ConfigException
from rvzr.target_desc import TargetDesc


class ARM64Executor(Executor):
    """ ARM-specific implementation of the executor """

    def __init__(self, enable_mismatch_check_mode: bool = False):
        super().__init__(enable_mismatch_check_mode)
        self._vendor = TargetDesc.get_vendor()
        if self._vendor != "ARM":
            raise ConfigException(
                "Attempting to run ARM64Executor executor on a non-ARM CPUs!\n"
                "Change the `executor` configuration option to the appropriate vendor value.")

    def _set_vendor_specific_features(self) -> None:
        pass
