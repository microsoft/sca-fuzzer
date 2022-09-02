# Revizor Modules and Interfaces

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
* `executor.py` - implements the x86 **Executor** portion of
  [revizor's architecture](architecture.md).
* `analyser.py` - implements the **Analyser** portion of
  [revizor's architecture](architecture.md).
* `postprocessor.py` - defines the `MinimizerViolation` class, used during
  `minimize` mode to reduce a violation-inducing test case down to a smaller
  size while still maintaining the violation-inducing behavior.
* `fuzzer.py` - implements `fuzz` mode that utilizes all main components to
  perform end-to-end hardware fuzzing.
* `coverage.py` - implements
* `factory.py` - defines a series of dictionaries that allows revizor to choose
  between various generation techniques, executors, analysers, etc. This will be
  especially useful when revizor supports multiple ISAs.
* `interfaces.py` - defines a number of classes used by the test case generator
  to generate valid assembly (`Instruction`, `BasicBlock`, `Operand`s, etc.)
* `isa\_loader.py` - defines the `InstructionSet` class, used to load an
  ISA's specifications from an XML file provided via the
  [command-line interface](cli.md).
* `service.py` - defines logging, statistical, and other services to all other
  modules within revizor.

## Assembly Generation

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

