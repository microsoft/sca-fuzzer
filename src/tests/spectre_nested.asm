.intel_syntax noprefix
MOV rcx, r14

# initialize eax and ebx with two random values
XOR rax, rax
XOR rbx, rbx
IMUL edi, edi, 2891336453
ADD edi, 12345
MOV eax, edi
IMUL edi, edi, 2891336453
ADD edi, 12345
MOV ebx, edi
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
SHL rbx, 61
SHR rbx, 61

# speculative offset:
# these shifts generate a random page offset, 64-bit aligned
SHL rax, 58
SHR rax, 52

# speculation
CMP rbx, 0
JE .l1
    # rbx != 0
    MOV rax, [rcx + rax]

    CMP rbx, 1
    JE .l2
    SHL rbx, 6  # * 64
    MOV rax, [rcx + rbx]

JMP .l2
.l1:
    # rbx == 0
    MOV rax, [rcx + 64]
.l2:
MFENCE
