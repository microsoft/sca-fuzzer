"""
File: Classes defining the actor abstraction.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import NamedTuple, Dict, Tuple
from enum import Enum
import random

from .target_desc import TargetDesc

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


class ElfSection(NamedTuple):
    """ Class representing the ELF section of an actor. """

    id_: int
    """ section id; will match the actor id if the actor IDs are ordered and contiguous """

    offset: int
    """ offset of the section in the ELF file """

    size: int
    """ size of the section in the ELF file """


def _pte_properties_to_mask(properties: dict,
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
            if def_bits_dict[bit_name][1] != properties[bit_name]:
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

    mode: ActorMode
    privilege_level: ActorPL
    name: ActorName
    data_properties: PageProperties
    data_ept_properties: PageProperties
    observer: bool
    _is_main: bool = False

    _id: ActorID
    _elf_section: ElfSection
    _elf_section_assigned: bool = False

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
        self._is_main = name == "main"

    @classmethod
    def from_dict(cls, actor_dict: Dict, target_desc: TargetDesc):
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

    def is_main(self) -> bool:
        """
        Check if the actor is the main actor.
        :return: True if the actor is the main actor, False otherwise
        """
        return self._is_main

    def assign_elf_section(self, section: ElfSection) -> None:
        """
        Assign an ELF section to the actor.
        :param section: ELF section
        :raises: AssertionError when attempting to assign a section with ID != 0 to the main actor
        """
        assert not self._is_main or section.id_ == 0, "Main actor must have section id 0"
        self._elf_section = section
        self._id = section.id_
        self._elf_section_assigned = True

    def elf_section(self) -> ElfSection:
        """
        Get the ELF section assigned to the actor.
        :return: ELF section
        :raises: AssertionError if the ELF section has not been assigned
        """
        assert self._elf_section_assigned, f"ELF section not assigned to actor {self.name}"
        return self._elf_section

    def get_id(self) -> ActorID:
        """
        Get the actor ID.
        :return: actor ID
        :raises: AssertionError if the ELF section has not been assigned
        """
        assert self._elf_section_assigned, "ELF section not assigned to actor"
        return self._id
