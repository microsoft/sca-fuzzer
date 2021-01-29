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
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
SHL rbx, 62
SHR rbx, 62

# speculation
CMP rbx, 0
JE .l1
    # rbx != 0
    MOV rax, [r14 + 64]
JMP .l2
.l1:
    # rbx == 0
    MOV rax, [r14]
.l2:

# speculative offset:
# these shifts generate a random page offset, 64-bit aligned
SHL rax, 58
SHR rax, 52
MOV rbx, [r14 + rax]

MFENCE
