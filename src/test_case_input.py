"""
File: Class representing a test case input, as well as related and derived classes.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import TYPE_CHECKING
import numpy as np

from .sandbox import SandboxLayout, DataArea

if TYPE_CHECKING:
    from .actor import ActorID

_ActorInput = np.dtype(
    [('main', np.uint64, SandboxLayout.data_area_size(DataArea.MAIN) // 8),
     ('faulty', np.uint64, SandboxLayout.data_area_size(DataArea.FAULTY) // 8),
     ('gpr', np.uint64, SandboxLayout.data_area_size(DataArea.GPR) // 8),
     ('simd', np.uint64, SandboxLayout.data_area_size(DataArea.SIMD) // 8),
     ('padding', np.uint64, SandboxLayout.data_area_size(DataArea.OVERFLOW_PAD) // 8)],
    align=False,
)
"""
_ActorInput data type represents the input for a single actor.
This array is designed to be easily serialized and deserialized into/from a binary file.
"""

_DATA_SIZE = _ActorInput['main'].itemsize + _ActorInput['faulty'].itemsize + \
    _ActorInput['gpr'].itemsize + _ActorInput['simd'].itemsize


class Input(np.ndarray):
    """
    Class that represents a single test case input.  It is a fixed-size array of
    64-bit unsigned integers, with a few addition methods for convenience.

    This class is typically produced by the input generator or parsed from a binary file.
    The class is typically consumed by the executor and the model to initialize their sandboxes.

    The number of elements in Input is equal to the number of actors multiplied by
    the number of elements in _ActorInput, i.e.,
        Input.size = n_actors * _ActorInput.size
    """

    seed: int = 0
    """ seed: The seed value used to generate this input """

    # ==============================================================================================
    # Constructors
    # ==============================================================================================
    def __new__(cls, n_actors: int = 1):
        obj = super().__new__(cls, (n_actors,), _ActorInput, None, 0, None, None)
        return obj

    def __array_finalize__(self, obj):
        if obj is None:
            return

    # ==============================================================================================
    # Class interface
    # ==============================================================================================
    @classmethod
    def data_size_per_actor(cls) -> int:
        """
        Get the size (in bytes) of the data area for a single actor.
        :return: Size, in bytes
        """
        return _DATA_SIZE

    @classmethod
    def n_data_entries_per_actor(cls) -> int:
        """
        Get the number of entries in the input array for a single actor.

        Note: This function is NOT equivalent to `data_size_per_actor`.
        This is because array entries are 64-bit integers.
        :return: Number of entries
        """
        return _DATA_SIZE // 8

    # ==============================================================================================
    # Object interface
    # ==============================================================================================
    def __hash__(self) -> int:  # type: ignore
        # hash of input is a hash of input data, registers and memory
        h = hash(self.tobytes())
        return h

    def __str__(self) -> str:
        return str(self.seed)

    def __repr__(self) -> str:
        return str(self.seed)

    def set_actor_data(self, actor_id: 'ActorID', data: np.ndarray) -> None:
        """
        Set the data for a single actor.
        :param actor_id: The actor ID
        :param data: The data to set
        :return: None
        :raises AssertionError: If the data array has an unexpected shape
        """
        assert data.shape == (self.itemsize // 8,), \
            "Data shape does not match the expected shape"

        # copy the data
        self[actor_id] = data.view(_ActorInput)

        # zero-fill the unused parts of the input
        self[actor_id]['padding'] = 0

    def save(self, path: str) -> None:
        """
        Save the input to a binary file.
        :param path: The path to the file
        """

        with open(path, 'wb') as f:
            f.write(self.tobytes())

    def load(self, path: str) -> None:
        """
        Load the input from a binary file.
        :param path: The path to the file
        """

        with open(path, 'rb') as f:
            contents = np.fromfile(f, dtype=np.uint64)
            n_actors = self.shape[0]
            for actor_id in range(n_actors):
                actor_start = actor_id * self.itemsize // 8
                actor_end = actor_start + self.itemsize // 8
                self.linear_view(actor_id)[:] = contents[actor_start:actor_end]

    def linear_view(self, actor_id: 'ActorID') -> np.ndarray:
        """
        Get a linear view of the input for a single actor;
        that is, a 1D array of 64-bit integers.
        :param actor_id: The actor ID
        :return: A linear view of the input for the actor
        """
        return self[actor_id].view((np.uint64, self[actor_id].itemsize // 8))

    def get_simd128_registers(self, actor_id: 'ActorID'):
        """
        Get a list of SIMD registers for a single actor.
        :param actor_id: The actor ID
        :return: A list of 128-bit SIMD registers
        """
        vals = []
        for i in range(0, _ActorInput['simd'].shape[actor_id], 2):
            vals.append(int(self[0]['simd'][i + 1]) << 64 | int(self[0]['simd'][i]))
        return vals


class InputTaint(Input):
    """
    Class that represents a taint vector for an input.

    The array is used to indicate which input elements influence contract traces. The number of
    elements in InputTaint is (and must be) identical to Input class.

    Each element is an boolean value: When it is True, the corresponding element of
    the input impacts the contract trace.
    """

    def __new__(cls, n_actors: int = 1):
        obj = super().__new__(cls, n_actors)  # type: ignore
        obj.fill(False)
        return obj
