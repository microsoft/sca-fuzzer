#!/usr/bin/env python3
import json
import subprocess
import os
import sys
import glob
import importlib.util
import requests
import re
import tempfile
import traceback
import argparse
import functools

# URL of the AArch64MappingInsn.inc file, for implicit registers information
MAPPING_INC_URL = "https://raw.githubusercontent.com/capstone-engine/capstone/46154e8605aaefdcca5fecf4ea88b92db5a40ad3/arch/AArch64/AArch64MappingInsn.inc"
# Path to save the downloaded AArch64MappingInsn.inc file
MAPPING_INC_PATH = "AArch64MappingInsn.inc"

# Default output path for the generated JSON file
DEFAULT_OUTPUT_JSON_PATH = "base_v2.json"

# constants from binutils:include/opcode/aarch64.h
F_ALIAS = (1 << 0)
F_COND = (1 << 4)
F_SF = (1 << 5)
F_PSEUDO = (1 << 21)


def gdb_main(func):
    def wrapper(*args, **kwargs):
        return_code = 0

        try:
            with open(fifo_path, "w") as output_fifo:
                output = func(*args, **kwargs) or ""
                output_fifo.write(output)
                output_fifo.flush()
        except Exception as e:
            return_code = getattr(e, "errno", -1)
            traceback.print_exception(type(e), e, e.__traceback__)
            print("GDB script failed.")

        gdb.execute("quit {}".format(return_code))

    return wrapper


@gdb_main
def gdb_assembler_main():
    featureset_str = args
    print(
        f"Fetching numeric featureset bits of {featureset_str} by inspecting aarch64-linux-gnu-as..."
    )

    # Disable verbose gdb output
    gdb.execute("set logging redirect on", to_string=True)
    gdb.execute("set logging file /dev/null", to_string=True)
    gdb.execute("set logging on", to_string=True)

    gdb.execute("break read_a_source_file", to_string=True)
    gdb.execute(f"r -o /dev/null -march={args} /dev/null", to_string=True)

    featureset_int = int(gdb.parse_and_eval("cpu_variant"))
    print(f"Numeric featureset bits: {hex(featureset_int)}")

    return hex(featureset_int)


def parse_mapping_file(path):
    with open(path, "r") as f:
        content = f.read()

    pattern = re.compile(
        r"{\s*(AArch64_\w+),\s*(ARM64_INS_\w+).*?{([^}]*)}.*?{([^}]*)}", re.DOTALL
    )
    insn_reg_map = {}

    for match in re.finditer(pattern, content):
        _, insn_with_prefix, regs_use, regs_mod = match.groups()
        insn_name = insn_with_prefix.replace("ARM64_INS_", "")  # Remove the prefix

        # Process only up to the first 0 encountered in regs_use and regs_mod
        regs_use = [
            reg.strip().replace("ARM64_REG_", "")
            for reg in regs_use.split(",")
            if reg.strip() and reg.strip() != "0"
        ]
        regs_mod = [
            reg.strip().replace("ARM64_REG_", "")
            for reg in regs_mod.split(",")
            if reg.strip() and reg.strip() != "0"
        ]

        insn_reg_map[insn_name] = {"regs_use": regs_use, "regs_mod": regs_mod}

    return insn_reg_map


def get_implicit_operands(insn, implicit_mapping):
    info = implicit_mapping.get(insn["name"])
    if info is None:
        info = {"regs_use": [], "regs_mod": []}

    implicit_operands = []

    for reg in info["regs_use"]:
        is_read = True
        is_write = reg in info["regs_mod"]

        if reg == "NZCV":
            width = 0
            type_ = "FLAGS"
            p = "r/w" if (is_read and is_write) else "w" if is_write else "r"
            values = [p, "", "", p, p, "", "", "", p]  # see get_spec.py for explanation
        else:
            width = 64
            type_ = "REG"
            values = [reg]

        implicit_operands.append(
            {
                "dest": is_write,
                "src": is_read,
                "type_": type_,
                "width": width,
                "values": values,
            }
        )

    if insn["control_flow"]:
        implicit_operands.append(
            {
                "dest": False,
                "src": True,
                "type_": "REG",
                "width": 64,
                "values": ["PC"],
            }
        )

    return implicit_operands


def get_operands_list(insn, raw_insn):
    operands_list = []
    index = 0

    # Add the condition code if the instruction is flagged as F_COND,
    # as this information isn't included in the operands list.
    if raw_insn["flags"] & F_COND == F_COND:
        operands_list.append("COND")

    while True:
        try:
            op = raw_insn["operands"][index]
            op_str = str(op).replace("AARCH64_OPND_", "")
            if op_str == "NIL":
                break  # Stop if we hit the NIL operand
            operands_list.append(op_str)
            if op_str.startswith("ADDR_UIMM") or op_str.startswith("ADDR_SIMM"):
                operands_list.append(op_str.replace("ADDR_", ""))
            index += 1
        except (gdb.error, IndexError):
            # If an IndexError is raised, we've reached the end of the operands.
            break
    return operands_list


def gdb_array_iter(gdb_arr):
    r = gdb_arr.type.range()
    for i in range(r[0], r[1]+1):
        yield gdb_arr[i]


def get_qualifiers(insn, raw_insn):
    qualifiers = []
    qualifier_type = gdb.lookup_type("enum aarch64_opnd_qualifier")

    for raw_qualifiers_row in gdb_array_iter(raw_insn["qualifiers_list"]):
        processed_row = []

        for k in gdb_array_iter(raw_qualifiers_row):
            qlf = str(k.cast(qualifier_type)).replace("AARCH64_OPND_QLF_", "")
            if qlf == "NIL":
                break

            processed_row.append(qlf)

        if processed_row:
            qualifiers.append(processed_row)

    return qualifiers or [[]]


def process_operand(insn, operand: str):
    supported_immediate_types = {
        "AIMM": ["[0-4095]"],
        "LIMM": ["bitmask"],
        "IMMR": ["[0-63]"],
        "IMMS": ["[0-63]"],
        "CCMP_IMM": ["[0-31]"],
        "NZCV": ["[0-15]"],
        "UIMM4": ["[0-15]"],
        "UIMM7": ["[0-127]"],
        "HALF": ["[0-65535]"],
        "BIT_NUM": ["[0-63]"],
        "SIMM9": ["[-256-255]"],
    }

    if operand in ("Ra", "Rd", "Rd_SP", "Rm", "Rn", "Rn_SP", "Rt"): # ignore 'Rm_EXT', 'Rm_SFT' for now
        type_ = "REG"
        width = 64
        is_dest = "Rd" in operand or (
            operand == "Rt" and insn["name"].startswith("LDR")
        )
        values = ["GPR"]
        if "SP" in operand:
            values.append("SP")
    elif operand.startswith("ADDR_PCREL") or operand.startswith("ADDR_ADRP"):
        type_ = "LABEL"
        width = 0
        is_dest = False
        values = []
    elif operand.startswith("ADDR_UIMM") or operand.startswith("ADDR_SIMM"):
        type_ = "MEM"
        width = 64
        is_dest = insn["name"].startswith("STR")
        values = []
    elif operand == "COND": # ignore COND1 for now which disallows AL,NV as condition
        type_ = "COND"
        width = 0
        is_dest = False
        values = []
    elif operand in supported_immediate_types:
        type_ = "IMM"
        width = 64
        is_dest = False
        values = supported_immediate_types[operand]
    else:
        return None

    return {
        "dest": is_dest,
        "src": not is_dest,
        "comment": operand,
        "type_": type_,
        "width": width,
        "values": values,
    }


def get_operands(insn, raw_insn):
    operands_general = []

    for operand in get_operands_list(insn, raw_insn):
        operand_info = process_operand(insn, operand)
        if operand_info is None:  # ignore instructions with unsupported operands_general
            return []

        operands_general.append(operand_info)

    operands_all_widths = []
    all_qualifiers = get_qualifiers(insn, raw_insn)

    for qualifier_row in all_qualifiers:
        operands = [o.copy() for o in operands_general]
        for i, qualifier in enumerate(qualifier_row):
            if qualifier == "W" or qualifier == "WSP":
                operands[i]["width"] = 32
            elif qualifier == "X" or qualifier == "SP":
                operands[i]["width"] = 64
            elif qualifier == "imm_0_31":
                assert operands[i]["type_"] == "IMM"
                operands[i]["values"] = ["[0-31]"]
            elif qualifier == "imm_0_63":
                assert operands[i]["type_"] == "IMM"
                operands[i]["values"] = ["[0-63]"]
        
        operands_all_widths.append(operands)

    return operands_all_widths


@functools.cache
def get_feature_bits(featureset_symbol):
    return int(gdb.parse_and_eval(featureset_symbol))


def get_aarch64_opcode_table_json(supported_features: int):
    # Access the aarch64_opcode_table
    table = gdb.parse_and_eval("aarch64_opcode_table")
    table_length = int(
        gdb.parse_and_eval(
            "sizeof(aarch64_opcode_table) / sizeof(aarch64_opcode_table[0])"
        )
    )
    table_length -= 1  # last instruction is intentionally non-valid

    raw_instructions = [table[i] for i in range(table_length)]
    implicit_mapping = parse_mapping_file(MAPPING_INC_PATH)

    # Extract the data
    processed_instructions = []
    for raw_insn in raw_instructions:
        featureset = str(raw_insn["avariant"]).split("<")[1].split(">")[0].replace(".lto_priv", "")
        featureset_bits = get_feature_bits(featureset)

        # only support instruction with features supported by the current CPU
        if featureset_bits & supported_features != featureset_bits:
            continue

        # ignore psuedo instructions
        if raw_insn["flags"] & (F_PSEUDO) != 0:
            continue

        name = raw_insn["name"].string().upper().replace(".C", ".")  # B.C should be B.
        iclass = str(raw_insn["iclass"])

        # not branch_reg as the fuzzer expects control_flow instructions to
        # branch to labels only
        control_flow = ("branch" in iclass) and ("branch_reg" not in iclass)

        basic_insn = {
            "name": name,
            "category": iclass,
            "control_flow": control_flow,
            "featureset": featureset,
            "featureset_bits": hex(featureset_bits),
        }

        operands_all_widths = get_operands(basic_insn, raw_insn)
        implicit_operands = get_implicit_operands(basic_insn, implicit_mapping)

        # process all possible supported widths of operands
        for i, operands in enumerate(operands_all_widths):
            insn = basic_insn.copy()

            # ignore instructions with labels as operands, as the fuzzer expects
            # all labels to be in control flow only
            if any(op["type_"] == "LABEL" for op in operands) and not control_flow:
                continue

            insn["operands"] = operands
            insn["implicit_operands"] = implicit_operands
            insn["qualifiers"] = ",".join(get_qualifiers(insn, raw_insn)[i])
            processed_instructions.append(insn)

    return sorted(processed_instructions, key=lambda i: i["name"])


@gdb_main
def gdb_libopcodes_main():
    json_output_path, featureset_int = args
    json_output = get_aarch64_opcode_table_json(featureset_int)

    with open(json_output_path, "w") as outfile:
        json.dump(json_output, outfile, indent=2)

    print(f"AArch64 instructions JSON saved at {json_output_path}.")


def download_mapping_file(url, path):
    response = requests.get(url)
    if response.status_code == 200:
        with open(path, "w") as f:
            f.write(response.text)
        print(f"Downloaded and saved to {path}")
    else:
        raise Exception(f"Failed to download file: HTTP {response.status_code}")


def find_libopcodes():
    # Find the libopcodes shared library file
    libopcodes_files = glob.glob("/usr/lib/aarch64-linux-gnu/libopcodes-*.so")
    if not libopcodes_files:
        raise FileNotFoundError("libopcodes shared library not found.")
    return libopcodes_files[0]



def check_required_packages():
    # the -dbg packges are for debug symbols for aarch64-linux-gnu-as and libopcodes
    required_packages = ["binutils", "gdb", "libbinutils-dbg", "binutils-aarch64-linux-gnu-dbg"]
    missing_packages = []

    print("Checking required packages for ARM64 specification production...")

    for package in required_packages:
        # Check if the package exists in the repository
        package_exists = subprocess.run(
            ["apt-cache", "search", f"^{package}$"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # If the package does not exist, then it shouldn't be considered missing
        # For instance, Debian bullseye does not have binutils-aarch64-linux-gnu-dbg
        # as it holds all the necessary debug information in libbinutils-dbg
        if not package_exists.stdout:
            continue

        # Check if the package is installed
        try:
            subprocess.run(
                ["dpkg", "-s", package],
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            print(f"{package} is installed.")
        except subprocess.CalledProcessError:
            missing_packages.append(package)

    if missing_packages:
        missing_str = " ".join(missing_packages)
        raise RuntimeError(
            f"The following package(s) are missing: {', '.join(missing_packages)}. "
            "Please install them to proceed. You can do this by running: "
            f"`sudo apt-get install {missing_str}`"
        )


def download_mapping_file(url, path):
    print(f"Checking if {os.path.basename(path)} exists...")

    if not os.path.exists(path):
        print(f"Downloading {os.path.basename(path)}...")
        response = requests.get(url)
        with open(path, "wb") as f:
            f.write(response.content)


def execute_gdb_with_script(script_file, target, args=None, readnow=False):
    print(f"Starting GDB with target {target} and script {script_file}...")
    script_path = os.path.abspath(script_file)

    # Create a named pipe (FIFO)
    fifo_path = tempfile.mktemp()
    os.mkfifo(fifo_path)

    gdb_command = [
        "gdb",
        target,
        "--batch",
        "-ex",
        "set pagination off",
        "-ex",
        "set confirm off",
        "-ex",
        "set max-value-size 10000000",
        "-ex",
        f"py fifo_path={repr(fifo_path)}",
        "-ex",
        f"py args={repr(args)}",
        "-ex",
        f"source {script_path}",
    ] + (["--readnow"] if readnow else [])

    with subprocess.Popen(gdb_command) as proc:
        with open(fifo_path, "r") as fifo:
            output = fifo.read()

        proc.wait()
        if proc.returncode != 0:
            raise subprocess.CalledProcessError(proc.returncode, proc.args)

    return output


def get_architecture_features():
    """Get the current architecture and feature set using gcc."""

    print("Getting current architecture revision and features...")
    output = subprocess.run(
        ["gcc", "-v", "-march=native", "/dev/null"],
        stderr=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    ).stderr

    # Fetch -march='XXX' in the output
    match = re.search(r"-march=([^'\s]+)", output)
    if match:
        print(f"Detected architecture and featureset (-march): {match.group(1)}")
        return match.group(1)
    else:
        raise RuntimeError("Architecture features not found.")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extracts supported opcodes of the current AArch64 processor using binutils and debug information."
    )
    parser.add_argument(
        "-o",
        "--output",
        default=DEFAULT_OUTPUT_JSON_PATH,
        help="The output JSON file to write the opcodes to.",
    )
    return parser.parse_args()


def standalone_main():
    args = parse_args()  # Parse command-line arguments

    # Function to be executed when this script is run outside GDB
    check_required_packages()
    download_mapping_file(MAPPING_INC_URL, MAPPING_INC_PATH)

    # obtain current processor featureset
    featureset_str = get_architecture_features()
    output = execute_gdb_with_script(__file__, "aarch64-linux-gnu-as", featureset_str)
    featureset_int = int(output, 16)

    # produce the JSON file, assuming current CPU supports features in featureset_int
    execute_gdb_with_script(
        __file__, find_libopcodes(), [args.output, featureset_int], readnow=True
    )


if __name__ == "__main__":
    if importlib.util.find_spec("gdb") is None:
        standalone_main()
    else:
        target = gdb.current_progspace().filename
        if "libopcodes" in target:
            gdb_libopcodes_main()
        elif "aarch64-linux-gnu-as" in target:
            gdb_assembler_main()
        else:
            raise RuntimeError(f"Unknown target for GDB script: {target}")
