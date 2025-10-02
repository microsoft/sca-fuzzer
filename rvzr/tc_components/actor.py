"""
File: Classes defining the actor abstraction.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations

from typing import Dict, Tuple, Final, Optional, TYPE_CHECKING
from enum import Enum
import random

from ..target_desc import TargetDesc, PTEBitName, PTEBitOffset

if TYPE_CHECKING:
    from ..config import PageConf, PagePropertyName, ActorConf
    from .test_case_code import CodeSection

    _PTEBitValue = bool
    _PTEDescriptor = Dict[PTEBitName, Tuple[PTEBitOffset, _PTEBitValue]]
    _PropertyMap = Dict[PagePropertyName, Tuple[PTEBitName, bool]]

ActorID = int
ActorName = str
PTEMask = int


class ActorMode(Enum):
    """ Enumeration class representing the execution mode of an actor (host or guest). """
    HOST = 0
    GUEST = 1


class ActorPL(Enum):
    """ Enumeration class representing the privilege level of an actor (kernel or user). """
    KERNEL = 0
    USER = 1


# ==================================================================================================
# Helper Functions to manage actor data properties
# ==================================================================================================
def _create_pte_mask(pte_descriptor: _PTEDescriptor, page_properties_to_set: PageConf,
                     page_property_to_pte_bit_name: _PropertyMap) -> PTEMask:
    """
    Create an architecture-specific page table entry (PTE) bitmask based on the actor's
    architecture-independent data properties. This bitmask is to be used by the executor
    and the model to set page table properties of actors.

    The function takes a dictionary `pte_descriptor` that describes each bit of the PTE for
    the target architecture. Each entry in the dictionary maps a bit name to a tuple containing
    the bit's offset in the PTE and its default value.

    The function modifies the default values based on the `page_properties_to_set` dictionary,
    which specifies the desired properties for the page table entry (this typically originates
    from config.yaml).

    As the names of the properties in `page_properties_to_set` may differ from the names used in
    the `pte_descriptor`, the function uses the `page_property_to_pte_bit_name` mapping to
    translate between the two.

    Optionally, if `page_properties_to_set['randomized']` is True, the function introduces
    randomness in the bitmask generation. Each bit has a chance of being set to its default
    value, with the probability proportional to the number of bits that differ from their
    default values.

    :param pte_descriptor: dictionary of default values for PTE bits
    :param page_properties_to_set: dictionary of page properties to set
    :param page_property_to_pte_bit_name: mapping from property names to PTE bit names
    :return: bitmask representing the PTE properties
    :raises: AssertionError if the properties dictionary is invalid
    """
    is_randomized = page_properties_to_set['randomized']

    # First, translate the architecture-independent properties to architecture-specific ones
    arch_specific_properties: Dict[PTEBitName, bool] = {}
    for property_name, value in page_properties_to_set.items():
        if property_name == 'randomized':
            continue
        assert property_name in page_property_to_pte_bit_name, \
            f"Actor data property {property_name} is not supported on this architecture"
        bit_name, is_inverted = page_property_to_pte_bit_name[property_name]
        if is_inverted:
            value = not value
        arch_specific_properties[bit_name] = value

    # If randomization is requested, calculate the probability of a bit being set to default value
    probability_of_default = 0.0
    if is_randomized:
        # calculate the number of non-default bits
        count_non_default = 0
        for bit_name in pte_descriptor:
            if pte_descriptor[bit_name][1] != arch_specific_properties[bit_name]:
                count_non_default += 1

        # the probability is proportional to the number of non-default bits
        # we use a formula that maps the probability in the range of roughly [0.5, 0.8] to
        # avoid having too low or too high probabilities
        a = count_non_default
        b = len(pte_descriptor)
        probability_of_default = (a / (a + b)) * 0.5 + 0.5

    # create the mask
    mask: PTEMask = 0
    for bit_name, new_value in arch_specific_properties.items():
        # get the bit offset and default value from the PTE descriptor
        bit_offset, default_value = pte_descriptor[bit_name]

        # The new value of the bit is either directly taken from the properties dictionary,
        # or it is randomly set to the default value based on the probability calculated above.
        bit_value: int
        if not is_randomized or new_value == default_value:
            bit_value = new_value
        else:
            set_to_default = random.random() < probability_of_default
            if set_to_default:
                bit_value = default_value
            else:
                bit_value = new_value

        # now set the bit in the mask
        bit_value = 1 if bit_value else 0
        mask |= bit_value << bit_offset
    return mask


# ==================================================================================================
# Actor Class
# ==================================================================================================
class Actor:
    """ Class representing an actor in a test case. """

    mode: Final[ActorMode]
    privilege_level: Final[ActorPL]
    name: Final[ActorName]
    data_properties: Final[PTEMask]
    data_ept_properties: Final[PTEMask]
    observer: Final[bool]
    is_main: Final[bool]

    _code_section: Optional[CodeSection] = None

    # ==============================================================================================
    # Constructors

    def __init__(self,
                 mode: ActorMode,
                 pl: ActorPL,
                 name: ActorName,
                 data_properties: PTEMask = 0,
                 data_ept_properties: PTEMask = 0,
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
        data_properties = _create_pte_mask(
            target_desc.pte_bits,
            actor_dict["data_properties"],
            target_desc.page_property_to_pte_bit_name,
        )
        data_ept_properties = _create_pte_mask(
            target_desc.epte_bits,
            actor_dict["data_ept_properties"],
            target_desc.page_property_to_pte_bit_name,
        )

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
