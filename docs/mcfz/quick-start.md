# Quick Start

This guide walks through a first MCFuzz run: installing the tool, building a
harness, and reading the report. For details on what MCFuzz does, read [MCFuzz at a Glance](overview.md).

## Requirements

* **Hardware:** An x86-64 CPU. The leakage model builds on DynamoRIO, which MCFuzz
uses to trace native x86-64 binaries. Other architectures are not supported.
* **Operating system:** A recent Linux distribution. Building the model and the
harness needs a C and C++ toolchain, the Clang/LLVM toolchain, and CMake, all of
which the steps below install.
* **Python:** Version 3.9 or later.

## Installation

MCFuzz ships with Revizor in one repository and runs from a source checkout
through the `mcfz.py` entry point.

### 1. Clone the repository and install the Python package

We recommend a virtual environment.

!!! note "MCFuzz currently lives on the `dev` branch"
    MCFuzz is not yet part of a tagged release, so for now you need the `dev`
    branch to get it. This is temporary: MCFuzz will ship on the default branch
    in the next release, after which the `-b dev` flag below can be dropped.

```bash
# install prerequisites: Git, plus Python's venv and pip modules
sudo apt-get install git python3-venv python3-pip

# get the source code
git clone -b dev https://github.com/microsoft/side-channel-fuzzer.git
cd side-channel-fuzzer

# create and activate a virtual environment
python3 -m venv ~/venv-mcfz
source ~/venv-mcfz/bin/activate

# install the package and its dependencies
pip install .
```

Check that the CLI runs:

```bash
./mcfz.py --help
```

### 2. Install AFL++

MCFuzz drives [AFL++](https://github.com/AFLplusplus/AFLplusplus) for its
input-generation stage. Build it (we'll use the default location `~/.local/afl` in this walkthrough, but you can put it anywhere):

```bash
# install build dependencies (clang and llvm provide AFL++'s LLVM
# instrumentation mode, which the harness is compiled with)
sudo apt-get install build-essential clang llvm

# get the source code and build it in the default location
mkdir -p ~/.local
git clone https://github.com/AFLplusplus/AFLplusplus.git ~/.local/afl
make -C ~/.local/afl
```

MCFuzz looks for `afl-fuzz` and `afl-cmin.py` in this directory. To use a
different location, set `afl_root` in the configuration file (run
`./mcfz.py --help-config` for the full list of options).

### 3. Install the DynamoRIO leakage model

The tracing stage runs each input under the DynamoRIO-based leakage model. The
repository's Makefile downloads DynamoRIO and builds the model and its adapter,
installing everything into `~/.local/dynamorio`.

```bash
# install build dependencies
sudo apt-get install cmake g++ g++-multilib wget

# download DynamoRIO and build the model
make -C rvzr/model_dynamorio
```

Check the installation:

```bash
~/.local/dynamorio/drrun -c ~/.local/dynamorio/libdr_model.so --list-tracers -- ls
# expected output includes:
#   ct
#   ...
```

To use a different location, set `model_root` in the configuration file (run
`./mcfz.py --help-config` for the full list of options).

## Running MCFuzz

### 1. Create the working directory

Everything in this walkthrough — the harness binaries, the policy, the
configuration file, the seed corpus, and the fuzzing artifacts — lives under a
single directory. Create it now:

```bash
mkdir -p ~/mcfz-quickstart
mkdir -p ~/mcfz-quickstart/work
mkdir -p ~/mcfz-quickstart/seeds
```

### 2. Build a harness

If you're using your own target, you need to create a harness, following the guide in [Building a Harness](harness.md).

If you want to try MCFuzz on a sample target, you can use the dummy harness provided in the repository. Build it and place the two harness binaries in the working directory with:

```bash
make -C mcfz/reference_harness HARNESS_BUILD_DIR=~/mcfz-quickstart
```

This produces `~/mcfz-quickstart/harness-native` and
`~/mcfz-quickstart/harness-afl`.

### 3. Prepare for fuzzing

Create a policy file that defines the secrecy policy of your target. The
reference harness has three input fields; the following policy marks the key as
secret and everything else as public. Save it as `~/mcfz-quickstart/policy.txt`:

```
key: private
plaintext: public
iv: public
```

Also create a configuration file that points MCFuzz at the two harness binaries
and the policy. Save the following as `~/mcfz-quickstart/config.yaml`:

```yaml
# Directory for all fuzzing artifacts, logs, and reports (must already exist).
working_dir: ~/mcfz-quickstart/work

# The two harness builds produced in step 2.
bin_native: ~/mcfz-quickstart/harness-native
bin_instrumented: ~/mcfz-quickstart/harness-afl

# How to invoke the harness: @# is the binary, @@ is the generated input file.
template_cmd: "@# -d @@ -p ~/mcfz-quickstart/policy.txt"

# The reference harness begins tracing at start_harness (the default is start_driver).
tracing_entrypoint: start_harness

# Seed corpus for AFL++ (created below).
afl_seed_dir: ~/mcfz-quickstart/seeds

# Tell the tool where to find AFL++
afl_root: ~/.local/afl

# Keep this first run short.
fuzzing_timeout_s: 60
```

Run `./mcfz.py --help-config` for the full list of options and their defaults.

Finally, AFL++ needs at least one valid seed to start from;
the reference harness ships one in `mcfz/reference_harness/corpora/`.
Copy it into the seed directory:

```bash
cp mcfz/reference_harness/corpora/seed0 ~/mcfz-quickstart/seeds/
```

### 4. Run the fuzzer

!!! warning "Disable ASLR"
    MCFuzz compares traces by address, so it needs addresses to stay fixed
    across runs. Disable address-space layout randomization before tracing:

    ```bash
    echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
    ```

    This setting resets on reboot. Re-apply it after each restart.


Run the full pipeline (all four stages: input generation, boosting, tracing, and
reporting) with:

```bash
./mcfz.py fuzz -c ~/mcfz-quickstart/config.yaml
```

You can also run the stages one at a time with the `fuzz_gen`, `boost`, `trace`,
and `report` subcommands; see [MCFuzz at a Glance](overview.md) for what each
does.

### 5. Read the report

MCFuzz writes its reports into the `stage4` subdirectory of the working
directory, in a set of JSON files. For example, `~/mcfz-quickstart/work/stage4/report_verbosity_1.json` will contain the lowest-verbosity report, which lists the number of leaks and their locations.

For the dummy harness, the lowest-verbosity report should list two leaks in
`dummy_lib.c` (the stand-in library called by `dummy_cipher_encrypt`), similar
to the following:

```json
{
    "schema_version": "1",
    "verbosity": 1,
    "metadata": {
        "tool": "mcfz",
        "generated_at": "2026-07-08T12:00:00+00:00",
        "target": "/home/you/mcfz-quickstart/harness-native",
        "allowlist": null
    },
    "summary": {
        "total_leaks": 2,
        "by_clause": {
            "seq": 2
        },
        "by_type": {
            "I": 1,
            "D": 1
        }
    },
    "leaks": [
        {
            "clause": "seq",
            "type": "I",
            "file": "dummy_lib.c",
            "line": 44
        },
        {
            "clause": "seq",
            "type": "D",
            "file": "dummy_lib.c",
            "line": 51
        }
    ]
}
```

(The `file` field is the source path as recorded in the binary's debug info. The
reference harness is compiled with a relative filename, so it appears here as
just `dummy_lib.c`.)

Each entry is one constant-time violation that depends on the secret key:

- The **I-type** (instruction, control-flow) leak at line 44 is the
  key-dependent branch `if (k & 0x01u)`: the direction of the rotation depends
  on a key bit, so two keys execute different instruction sequences.
- The **D-type** (data, memory-access) leak at line 51 is the key-indexed table
  lookup `x ^= g_sbox[k]`: the load address depends on a key byte, so two keys
  access different memory addresses.

The `clause` is `seq` because both leaks are architectural — visible in
sequential, non-speculative execution. Marking the key `public` in the policy
would make the harness constant-time with respect to secrets, and MCFuzz would
report no leaks.
