"""
File: Module responsible for boosting inputs by generating public-equivalent variants.

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from __future__ import annotations
from typing import TYPE_CHECKING, Final, List, Tuple

import os

if TYPE_CHECKING:
    from .config import Config

CONF_SIZE: Final[int] = 0x10  # Size of the config data in bytes


class Boost:
    """
    Class responsible for boosting inputs by generating public-equivalent variants.
    """

    def __init__(self, config: Config) -> None:
        self._config = config
        self._boosting_factor = config.num_secrets_per_class

    def _generate_from_reference(self, wd: str, reference_input: str) -> None:
        """
        Given a reference input, generate more inputs that will contain the same public data,
        but the secret (private) data will be randomly generated
        (the size of the secret data will be the same).

        The input file contains two sections: config and data.

        Config section (16 bytes total):
        * Bytes 0-1: irrelevant for this function.
        * Byte 2: Private-to-public ratio - determines the layout of the data section.
          E.g., if this byte is 1 and the data size is 1024 bytes, then
          priv_size = (1 / 256) * 1024 = 4 bytes, and
          pub_size = (255 / 256) * 1024 = 1020 bytes.
        * Bytes 3-7: Unused (reserved for future use)
        * Bytes 8-15: irrelevant for this function.

        Data section (variable size):
        * Private data (priv_size bytes): This region will be randomized.
        * Public data (pub_size bytes): This region will be copied from the reference input.

        :param wd: Working directory to store the generated inputs
        :param reference_input: Path to the reference input file
        """
        # Read the reference input to determine the sizes of public and private data
        with open(reference_input, 'rb') as f:
            ref_data = f.read()

        if len(ref_data) < CONF_SIZE + 2:  # Public and private data must be present
            raise ValueError("Reference input is too small to contain config and data sections.")

        data_size = len(ref_data) - CONF_SIZE
        priv_size = (ref_data[2] * data_size) // 256
        pub_size = data_size - priv_size
        if len(ref_data) < (CONF_SIZE + pub_size):
            raise ValueError("Reference input is too small for the calculated public data size.")

        # Copy the reference input to the working directory
        with open(os.path.join(wd, "000.bin"), 'wb') as dest_file:
            dest_file.write(ref_data)

        # Generate the secret inputs
        config_data = ref_data[:CONF_SIZE]
        pub_data = ref_data[CONF_SIZE + priv_size:CONF_SIZE + priv_size + pub_size]
        for i in range(1, self._boosting_factor):
            priv_data = os.urandom(priv_size)
            dest_path = os.path.join(wd, f"{i:03}.bin")
            with open(dest_path, 'wb') as dest_file:
                dest_file.write(config_data + priv_data + pub_data)

    def _collect_reference_inputs(self) -> List[Tuple[str, str]]:
        """
        Collect all reference input files from the minimized corpus directory.

        Reads from ``<stage1_wd>/minimized``, which is produced by
        :py:meth:`FuzzGen.minimize` after fuzzing.

        :return: List of (filename, absolute_path) for each reference input
        :raises FileNotFoundError: If the minimized directory does not exist
        """
        minimized_dir = os.path.join(self._config.stage1_wd, "minimized")

        if not os.path.isdir(minimized_dir):
            raise FileNotFoundError(
                f"Minimized corpus directory not found at {minimized_dir}. "
                "Did the fuzzing stage complete successfully?"
            )

        inputs: List[Tuple[str, str]] = []
        for fname in sorted(os.listdir(minimized_dir)):
            fpath = os.path.join(minimized_dir, fname)
            if os.path.isfile(fpath):
                inputs.append((fname, fpath))

        return inputs

    def generate(self) -> None:
        """
        Generate public-equivalent variants for each reference input generated during fuzzing.
        The variants will contain the same public data, but the secret (private) data will be
        randomly generated (though the size of the secret data will be the same).
        The variants will be stored in the stage 2 working directory.

        :return: None
        :raises FileNotFoundError: If the fuzzing working directory does not exist
        :raises OSError: If there is an error creating directories or files
        """

        ref_inputs = self._collect_reference_inputs()

        for ref_input, ref_input_path in ref_inputs:
            dest_dir = os.path.join(self._config.stage2_wd, ref_input)
            os.makedirs(dest_dir, exist_ok=True)

            try:
                self._generate_from_reference(dest_dir, ref_input_path)
            except ValueError as ve:
                print(f"[Boosting] Skipping input '{ref_input}': {ve}")
                os.rmdir(dest_dir)
