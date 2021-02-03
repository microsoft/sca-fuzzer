# CT-COND

The contract includes the following categories of instructions: 
NOP, binary operations, bit-byte operations, data conversion, data transfer, flag operations, SETCC, logical operations, POP, PUSH, conditional branches.
It excludes instructions IMUL, MUL, IDIV, BSF, BSR, BT.
A complete list of instructions is defined below, in "Instruction List".

The contract defines 5 instruction classes: 
- NoSpec-NoMem: instructions without memory operands, excluding conditional branches.
- NoSpec-Read: instructions that read (load) from memory, excluding conditional branches.
- NoSpec-Write: instructions that write (store) to memory, excluding conditional branches.
- Spec-NoMem: conditional branches without memory operands.

# Instruction Class Definitions
## NoSpec-NoMem
Observation Mode:
None

Execution Mode:
None

## NoSpec-Read
Instruction format "INST (ADDR), destination"

Observation Mode:
```
contract_trace += ADDR
```

Execution Mode:
None

## NoSpec-Write
Instruction format "INST source, (ADDR)"

Observation Mode:
```
contract_trace += ADDR
```

Execution Mode:
None


## Spec-NoMem
Instruction format "JCC (DEST)"

Observation Mode:
None

Execution Mode:
```
Checkpoint();
IF NOT condition THEN
    tempEIP := EIP + SignExtend(DEST);
    IF OperandSize = 16
        THEN tempEIP := tempEIP AND 0000FFFFH;
    FI;
    EIP := tempEIP
FI
```

# Instruction List

NoSpec-NoMem:
- ADD r8, imm8
- AND r8, imm8
- ...

NoSpec-Read:
- ADD m8, imm8
- AND m8, imm8
- ...

NoSpec-Write:
- ADD r8, m8
- AND r8, m8
- ...

Spec-NoMem:
- JA rel8
- JAE rel8
- JB rel8
- JBE rel8
...