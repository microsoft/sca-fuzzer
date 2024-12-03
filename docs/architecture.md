# Revizor Architecture

Below is a high-level overview of Revizor's architecture and its key modules.

[THE FOLLOWING IS A WORK IN PROGRESS]

![architecture](assets/arch.png)

Revizor has **five** chief components:

1. Test Case Generator
2. Input Generator
3. Model
4. Executor
5. Analyser

The **Test Case Generator** and **Input Generator** are responsible for
generating random test cases to be run through the **Model** and **Executor**.
The results are examined by the **Analyser** for contract violations.

### Test Case (Program) Generator

The TCG is responsible for generating random assembly test cases. It takes an
Instruction Set Specification as input in order for it to understand the
instructions and syntax it can use for generation.

### Input Generator

The IG is responsible for generating the *inputs* that are passed into a test
case created by the TCG. Largely, this means **register** and **memory** values
that the microarchitecture will be primed with before executing the test case.
In this way, a single test case program can be run across several different
inputs, allowing for multiple contract traces (and later, hardware traces) to be
collected for analysis.

###  Model

The Model's job is to accept test cases and inputs from the TCG & IG and
*emulate* the test case to collect **contract traces**. A single test case seeded
with several inputs (`N` inputs) will create several contract traces (`N`
contract traces) as the model's output. These are passed to the Analyser to
determine **input classes**.

### Executor

The Executor, on the other side from the Model, is responsible for running the
*same* test cases (with the *same* inputs) on physical hardware to collect
**hardware traces**. Hardware traces from the same input class are collected and
studied by the Analyser to detect **contract violations**.

### Analyser

The Analyser receives contract traces from the Model and hardware traces from
the Executor to accomplish two primary goals:

1. Compare contract traces to set up **input classes**.
2. Compare hardware traces to detect **contract violations**.


## Revizor Modules and Interfaces

Revizor's implementation and [architecture](architecture.md) is separated into
multiple Python files:

* `cli.py` - implements the command-line interface of revizor.
* `config.py` - implements parsing and managing of revizor's YAML configuration
  file.
* `generator.py` - implements the **Test Case Generator** portion of
  [revizor's architecture](architecture.md).
* `input_generator.py` - implements the **Input Generator** portion of
  [revizor's architecture](architecture.md).
* `model.py` - implements the Unicorn-based **Model** portion of
  [revizor's architecture](architecture.md).
* `executor.py` - implements the **Executor** portion of
  [revizor's architecture](architecture.md).
* `analyser.py` - implements the **Analyser** portion of
  [revizor's architecture](architecture.md).
* `postprocessor.py` - defines the `MinimizerViolation` class, used during
  `minimize` mode to reduce a violation-inducing test case down to a smaller
  size while still maintaining the violation-inducing behavior.
* `fuzzer.py` - implements `fuzz` mode that utilizes all main components to
  perform end-to-end hardware fuzzing.
* `factory.py` - used to configure revizor accordingly to the user provided
  YAML configuration. Implements a simplified version of the Factory pattern:
  Defines a series of dictionaries that allows revizor to choose
  between various contract, generation techniques, executors, analysers, etc.
  In future, it be also used to implement  multiple-ISA support.
* `interfaces.py` - defines abstract classes (i.e., interfaces) of all main
  components of revizor (e.g., abstract  `Executor`, `Model`, `TestCase`,
   `Input`, etc)
* `isa\_loader.py` - defines the `InstructionSet` class, used to load an
  ISA's specifications from a JSON file provided via the
  [command-line interface](user/cli.md).
* `service.py` - defines logging, statistical, and other services to all other
  modules within revizor.

### Architecture-specific Implementation

The modules above are ISA-independent. The architecture-specific implementations
are located in the subdirectories. For example, the implementation of the modules
for the x86-64 architecture is located in `src/x86/`. It's structure largely
mirrors the main modules of revizor (e.g., `x86_model.py` contains x86-specific
parts of the **Model** module). The only unique parts are:

* `*_target_desc.py` - defines constants describing the ISA (e.g., a list of
  available registers) and some helper functions.
* `get_spec.py` - a script for transforming the ISA description provided
  by the CPU vendor (different for every vendor) into a unified JSON format
* `executor/` - contains a low-level implementation of the executor. The
  implementation will be different for each architecture. For black-box x86 CPUs,
  it is a Linux kernel module.

### Abstract Test Case

This describes a number of Python classes within revizor that define parts of an
assembly test case. Revizor's TCG uses them to generate syntactically-valid
assembly.

#### `OperandSpec`

The `OperandSpec` class defines a set of valid operands for any given assembly
instruction. Each `InstructionSpec` object (described below) contains a list of
these operand specifications. It contains properties such as:

* The `type` of operand
* The `width` of the operand
* Whether or not the operand is a `src` or `dest` operand

#### `InstructionSpec`

This class represents a single instruction specification. It contains a name
(i.e. the actual instruction mnemonic, such as `ADD`) and a list of
`OperandSpec`s, defining valid operands for the instruction. It also has a
number of boolean flags that indicate unique attributes about the instruction,
such as:

* If the instruction contains a memory write
* If the instruction is a control-flow instruction

#### `Operand`

The `Operand` class defines an actual operand to be used in an instruction
placed into the TCG's generated test case (not to be confused with
`OperandSpec`, which is a set of rules used to define possible operand choices
for an instruction). This is an **abstract base class** that provides a number
of sub-classes:

* `RegisterOperand`
* `MemoryOperand`
* `ImmediateOperand`
* `LabelOperand`
* `AgenOperand`
* `FlagsOperand`

#### `Instruction`

Similar to the relationship between `OperandSpec` and `Operand`, the
`Instruction` class defines an actual instruction, constrained by an
`InstructionSpec`, that is used during test case generation. It contains a list
of `Operand`s and is linked to its neighboring instructions via object
references.

#### `BasicBlock`

Thisi class represents a single basic block within the generated test case (a
**basic block** is a straight-line sequence of assembly instructions that has a
single entry and exit point). It contains a list of all instructions contained
within, references to its successor basic block(s), and a list of "terminator"
instructions (instructions that exit the basic block, such as a branch).

#### `Function`

This object represents a collection of basic blocks that form a function. It has
an "entry" basic block and an "exit" basic block, along with a list of all basic
blocks that comprise the function.

#### `TestCaseDAG`

**DAG** is short for **Directed Acyclic Graph**. This object represents the
*entire* test case's control flow. It contains a list of functions that, within,
define all instructions to be written out to the test case's assembly file.
