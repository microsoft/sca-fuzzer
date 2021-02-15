.intel_syntax noprefix
MOV rcx, r14

# generate a random value
IMUL edi, edi, 2891336453
ADD edi, 12345
MOV eax, edi
IMUL edi, edi, 2891336453
ADD edi, 12345
MOV ebx, edi
LFENCE

# delay the jump
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

# select a target based on the random value
LEA rdx, [rip + .l1]
LEA rsi, [rip + .l2]
CMP rbx, 0
CMOVE rsi, rdx

# speculation
JMP rsi
.l1:
    # rbx = 0
    MOV rdx, [rcx + 64]
    JMP .l3

.l2:
    # rbx != 0
    AND rax, 0b110000000  # reduce the number of possibilities
    MOV rdx, [rcx + rax]
    JMP .l3
.l3:
MFENCE
