"""
File: Configuration part specific to the inspector.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""

from typing import Dict, List, Optional, Tuple, Any

class LeakageInspectorConfig:
    """
    Configuration part specific to the inspector.
    """
    declassified: List[str]
    known_syms: Dict[str, List[int]]
    key: List[str]
    dont_follow: List[str]
    follow_mem_uses: bool

    def __init__(self):
        self.declassified = []
        self.known_syms = []
        self.key = []
        # NOTE: These are used as size register for AVX instructions. Since they are not logged,
        # they create a lot of noise. We decided to silence them, although potentially
        # also these could be a source for differential use-def differences.
        self.dont_follow = ["K0", "K1", "K2", "K3", "K4", "K5", "K6", "K7"]
        # If the addresses are different, of course the values can differ, hence we stop the
        # analysis there.
        self.follow_mem_uses = False

    def parse(self, yaml_data: Dict[str, Any]) -> None:
         """
         Parse the values from a dictionary.
         """
         self.declassified = yaml_data.get("declassified", self.declassified)
         self.known_syms = yaml_data.get("known_syms", self.known_syms)
         self.key = yaml_data.get("key", self.key)
         self.dont_follow = yaml_data.get("dont_follow", self.dont_follow)
         self.follow_mem_uses = yaml_data.get("follow_mem_uses", self.follow_mem_uses)

    def get_sym_annotation(self, address: str) -> Optional[Tuple[str, int]]:
        """
        If the address is in the range of a known symbol (defined in the config) get symbol name
        and offset.
        """
        for sym_name, sym_address in self.known_syms.items():
                start = sym_address[0]
                size = sym_address[1]
                if address >= start and address < start + size:
                    return sym_name, address-start
        return None
