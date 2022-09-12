"""
File: arm64-specific configuration options

Copyright (C) Microsoft Corporation
SPDX-License-Identifier: MIT
"""
from typing import List

# x86_option_values attribute MUST be the first attribute in the file
arm64_option_values = {
    'executor_mode': ['P+P', 'F+R', 'E+R'],
}

arm64_instruction_categories: List[str] = [
    "general",  # base instruction set
]
arm64_instruction_blocklist: List[str] = [
    "ADCS",
    "ADDG",
    "ADDS",
    "ADR",
    "ADRP",
    # "AND",
    "ANDS",
    "ASRV",
    "AUTDA",
    "AUTDB",
    "AUTDZA",
    "AUTDZB",
    "B",
    "BC.",
    "BFM",
    "BIC",
    "BICS",
    "BL",
    "CBNZ",
    "CBZ",
    "CCMN",
    "CCMP",
    "CLS",
    "CLZ",
    "CRC32B",
    "CRC32CB",
    "CRC32CH",
    "CRC32CW",
    "CRC32CX",
    "CRC32H",
    "CRC32W",
    "CRC32X",
    "CSEL",
    "CSINC",
    "CSINV",
    "CSINV",
    "CSNEG",
    "EON",
    "EOR",
    "ERETAA",
    "ERETAB",
    "EXTR",
    "GMI",
    "IRG",
    "LDR",
    "LDRB",
    # "LDRH",
    "LDRSB",
    "LDRSH",
    "LDRSW",
    "LSLV",
    "LSRV",
    "MADD",
    "MSUB",
    "MOVK",
    "MOVN",
    "MOVZ",
    "ORR",
    "ORN",
    "PACDA",
    "PACDB",
    "PACDZA",
    "PACDZB",
    "PACGA",
    "RBIT",
    "RETAA",
    "RETAB",
    "RET",
    "REV",
    "REV16",
    "REV32",
    "RMIF",
    "RORV",
    "SBC",
    "SBCS",
    "SBFM",
    "SDIV",
    "SETF16",
    "SETF8",
    "SMADDL",
    "SMSUBL",
    "SMULH",
    # "STR",
    "STRB",
    "STRH",
    "SUBG",
    "SUBP",
    "SUBPS",
    "SUBS",
    "UBFM",
    "UDF",
    "UDIV",
    "UMADDL",
    "UMSUBL",
    "UMULH",
]
arm64_register_blocklist: List[str] = ["WSP", "SP", "XZR", "WZR"]
