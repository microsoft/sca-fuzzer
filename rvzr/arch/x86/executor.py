"""
File: Implementation of executor for x86 architecture

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from rvzr.executor import Executor, km_write
from rvzr.config import CONF, ConfigException
from rvzr.target_desc import TargetDesc


def _set_x86_common_features() -> None:
    km_write("1" if getattr(CONF, 'x86_executor_enable_ssbp_patch') else "0",
             "/sys/rvzr_executor/enable_ssbp_patch")
    km_write("1" if getattr(CONF, 'x86_executor_enable_prefetcher') else "0",
             "/sys/rvzr_executor/enable_prefetcher")
    km_write("1" if getattr(CONF, 'x86_enable_hpa_gpa_collisions') else "0",
             "/sys/rvzr_executor/enable_hpa_gpa_collisions")


class X86IntelExecutor(Executor):
    """ Intel-specific implementation of the executor """

    def __init__(self, enable_mismatch_check_mode: bool = False):
        super().__init__(enable_mismatch_check_mode)
        self._vendor = TargetDesc.get_vendor()
        if self._vendor != "Intel":
            raise ConfigException(
                "Attempting to run Intel executor on a non-Intel CPUs!\n"
                "Change the `executor` configuration option to the appropriate vendor value.")

    def _set_vendor_specific_features(self) -> None:
        _set_x86_common_features()

        handled_faults = CONF._handled_faults  # pylint: disable=protected-access  # FIXME
        km_write("1" if "BR" in handled_faults else "0", "/sys/rvzr_executor/enable_mpx")


class X86AMDExecutor(Executor):
    """ AMD-specific implementation of the executor """

    def __init__(self, enable_mismatch_check_mode: bool = False):
        super().__init__(enable_mismatch_check_mode)
        self._vendor = TargetDesc.get_vendor()
        if self._vendor != "AMD":
            raise ConfigException(
                "Attempting to run AMD executor on a non-AMD CPUs!\n"
                "Change the `executor` configuration option to the appropriate vendor value.")

    def _set_vendor_specific_features(self) -> None:
        _set_x86_common_features()
