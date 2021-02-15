.intel_syntax noprefix
MOV rcx, r14

# initialize eax and ebx with two random values
IMUL edi, edi, 2891336453
ADD edi, 12345
MOV eax, edi
IMUL edi, edi, 2891336453
ADD edi, 12345
MOV ebx, edi
LFENCE

# delay the cond. jump
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
    MOV rax, [rcx + rax]
JMP .l2
.l1:
    # rbx == 0
    MOV rax, [rcx]
.l2:
MFENCE
