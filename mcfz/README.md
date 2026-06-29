# McFuzz — Model-based Constant-time Fuzzer

> **Status:** This module is experimental. Its interfaces, configuration keys,
> and the harness contract may (and likely will) change.

McFuzz (`mcfz`) detects software side-channel leaks (constant-time violations)
in compiled binaries. It checks the **non-interference** property: the
microarchitectural *contract trace* of a program must not depend on its secret
(private) inputs. If two executions with identical public inputs but different
secret inputs produce different traces, McFuzz reports a leak.

McFuzz reuses the same leakage model as the hardware fuzzer (Revizor),
implemented as a DynamoRIO client (see `rvzr/model_dynamorio`). The model is
assumed to have already been validated against the target CPU, so a trace
divergence is attributed to the *software* under test rather than to the model.

McFuzz does not test arbitrary programs directly. It drives a **harness** — a
small wrapper around the code under test that exposes a fixed interface (a data
blob `-d` and a policy file `-p`) and a named entry function where tracing
begins. The policy file classifies each input field as public or private.

> 📖 **For the full guide** — concepts, prerequisites, the harness contract, the
> complete configuration reference, the working-directory layout, how to read a
> report, and troubleshooting — see [docs/mcfz-usage.md](../docs/mcfz-usage.md).

---

## Pipeline

McFuzz runs in four stages, each backed by a CLI subcommand:

1. **`fuzz_gen`** — AFL++ generates a diverse corpus of inputs that exercises
   many code paths in the instrumented binary.
2. **`boost`** — For each corpus input, McFuzz creates variants that keep the
   public bytes intact but randomize the private bytes, forming
   public-equivalence classes.
3. **`trace`** — Each input is executed under the DynamoRIO leakage model on the
   native binary to collect contract traces.
4. **`report`** — Within each equivalence class, traces are compared; divergences
   are mapped back to source lines via DWARF debug info and written to JSON.

The `fuzz` subcommand runs all four stages in sequence. The `details` subcommand
drills down into a specific reported violation.

---

## Configuration

All run parameters — the target command, the binary paths, timeouts, the working
directory, etc. — are specified in a YAML configuration file passed via `-c`. The
CLI subcommands take no other run parameters.

Key required options:

- `working_dir` — directory for all fuzzing artifacts, logs, and reports.
- `template_cmd` — command template for invoking the harness, using `@#` as the
  placeholder for the binary and `@@` for the generated input file
  (e.g. `"@# -d @@ -p policy.txt"`).
- `bin_instrumented` — AFL++-instrumented harness build (used in `fuzz_gen`).
- `bin_native` — native (non-instrumented) harness build (used in `trace`).
- `afl_seed_dir` — seed corpus directory for AFL++.

Print the full list of options and their defaults with:

```
./mcfz.py --help-config
```

---

## Usage

Disable ASLR first so addresses are deterministic across runs:

```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

Run the whole pipeline at once:

```
./mcfz.py fuzz -c config.yaml
```

Or run the stages individually:

```
./mcfz.py fuzz_gen -c config.yaml   # Stage 1: AFL++ input generation
./mcfz.py boost    -c config.yaml   # Stage 2: public-equivalent variants
./mcfz.py trace    -c config.yaml   # Stage 3: contract tracing
./mcfz.py report   -c config.yaml   # Stage 4: non-interference analysis
```

Drill down into a specific violation (e.g. at program counter `0x3039`):

```
./mcfz.py details -c config.yaml --pc 0x3039 --output-dir ./drill
```
