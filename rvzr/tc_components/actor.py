"""
File: Classes defining the actor abstraction.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import Dict, Tuple, Final, Optional, TYPE_CHECKING
from enum import Enum
import random

if TYPE_CHECKING:
    from ..target_desc import TargetDesc
    from ..config import PageConf, ActorConf
    from .test_case_code import CodeSection

ActorID = int
ActorName = str
PageProperties = int


class ActorMode(Enum):
    """ Enumeration class representing the execution mode of an actor (host or guest). """
    HOST = 0
    GUEST = 1


class ActorPL(Enum):
    """ Enumeration class representing the privilege level of an actor (kernel or user). """
    KERNEL = 0
    USER = 1


def _pte_properties_to_mask(properties: PageConf,
                            def_bits_dict: Dict[str, Tuple[int, bool]]) -> PageProperties:
    """
    Convert a dictionary of PTE properties to a bitmask, later used to set the attributes
    of faulty pages in the executor.
    If properties['randomized'] is set to True, each bit has a chance of retaining its
    default value. Otherwise, the mask is created with the exact values from the dictionary.

    :param properties: dictionary of PTE properties
    :param def_bits_dict: dictionary of default values for PTE bits
    :return: bitmask representing the PTE properties
    :raises: AssertionError if the properties dictionary is invalid
    """

    # calculate the probability of a bit being set to its default value
    probability_of_default = 0.0
    if properties['randomized']:
        count_non_default = 0
        for bit_name in def_bits_dict:
            # transform non_executable to executable
            if bit_name == "non_executable":
                p_value = not properties["executable"]
            else:
                p_value = properties[bit_name]

            if def_bits_dict[bit_name][1] != p_value:
                count_non_default += 1
        probability_of_default = count_non_default / len(properties)

    # create the mask
    mask: PageProperties = 0
    for bit_name in def_bits_dict:
        bit_offset, default_value = def_bits_dict[bit_name]

        # transform non_executable to executable
        if bit_name == "non_executable":
            p_value = not properties["executable"]
        else:
            p_value = properties[bit_name]

        if random.random() < probability_of_default:
            p_value = default_value

        bit_value = 1 if p_value else 0
        mask |= bit_value << bit_offset
    return mask


class Actor:
    """ Class representing an actor in a test case. """

    mode: Final[ActorMode]
    privilege_level: Final[ActorPL]
    name: Final[ActorName]
    data_properties: Final[PageProperties]
    data_ept_properties: Final[PageProperties]
    observer: Final[bool]
    is_main: Final[bool]

    _code_section: Optional[CodeSection] = None

    # ==============================================================================================
    # Constructors

    def __init__(self,
                 mode: ActorMode,
                 pl: ActorPL,
                 name: ActorName,
                 data_properties: PageProperties = 0,
                 data_ept_properties: PageProperties = 0,
                 is_observer: bool = False) -> None:
        self.mode = mode
        self.privilege_level = pl
        self.name = name
        self.data_properties = data_properties
        self.data_ept_properties = data_ept_properties
        self.observer = is_observer
        self.is_main = name == "main"

    @classmethod
    def from_dict(cls, actor_dict: ActorConf, target_desc: TargetDesc) -> 'Actor':
        """
        Create an actor based on a dictionary of actor properties.
        :param actor_dict: dictionary of actor properties
        :param target_desc: target description
        :return: Actor object
        :raises: ValueError if actor_dict is malformed
        """
        # actor mode of execution
        if actor_dict['mode'] == "host":
            mode = ActorMode.HOST
        elif actor_dict['mode'] == "guest":
            mode = ActorMode.GUEST
        else:
            raise ValueError(f"Invalid actor mode: {actor_dict['mode']}")

        # privilege level
        if actor_dict['privilege_level'] == "kernel":
            pl = ActorPL.KERNEL
        elif actor_dict['privilege_level'] == "user":
            pl = ActorPL.USER
        else:
            raise ValueError(f"Invalid actor privilege level: {actor_dict['privilege_level']}")

        # PTE and EPTE properties
        data_properties = _pte_properties_to_mask(actor_dict["data_properties"],
                                                  target_desc.pte_bits)
        data_ept_properties = _pte_properties_to_mask(actor_dict["data_ept_properties"],
                                                      target_desc.epte_bits)

        # create the actor
        return Actor(
            mode,
            pl,
            actor_dict["name"],
            data_properties=data_properties,
            data_ept_properties=data_ept_properties,
            is_observer=actor_dict["observer"],
        )

    @classmethod
    def create_main(cls) -> 'Actor':
        """
        Create the main actor with default properties.
        :return: Actor object
        """
        return Actor(ActorMode.HOST, ActorPL.KERNEL, "main")

    # ==============================================================================================
    # Public methods
    def assign_code_section(self, section: CodeSection) -> None:
        """ Assign a code section to the actor. """
        assert self._code_section is None, f"Code section already assigned to actor {self.name}"
        self._code_section = section

    def code_section(self) -> CodeSection:
        """ Get the code section assigned to the actor. """
        assert self._code_section is not None, f"Code section not assigned to actor {self.name}"
        return self._code_section

    def get_id(self) -> ActorID:
        """
        Get the actor ID.
        :return: actor ID
        :raises: AssertionError if the ELF section has not been assigned
        """
        assert self._code_section is not None, f"Code section not assigned to actor {self.name}"
        assert self._code_section.id_ is not None, \
            "assign_elf_data was not called on the child CodeSection"
        return self._code_section.id_
