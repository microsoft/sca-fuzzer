.intel_syntax noprefix
LFENCE

# delay the cond. jump
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
SHL rbx, 62
SHR rbx, 62

# speculative offset:
# these shifts generate a random page offset, 64-bit aligned
SHL rax, 58
SHR rax, 52

# speculation
CMP rbx, 0
JE .l1
    # rbx != 0
    MOV rax, [r14 + rax]
JMP .l2
.l1:
    # rbx == 0
    MOV rax, [r14 + 64]
.l2:
MFENCE
