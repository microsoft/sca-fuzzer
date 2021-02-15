.intel_syntax noprefix
MOV rcx, r14

# eax = random
IMUL edi, edi, 2891336453
ADD edi, 12345
MOV eax, edi
# ebx = random
IMUL edi, edi, 2891336453
ADD edi, 12345
MOV ebx, edi
LFENCE

# trun rax into a page offset
SHL rax, 58
SHR rax, 52

# select a target based on the random value
LEA rdx, [rip + .l1]
LEA rsi, [rip + .l2]
SHL rbx, 62
SHR rbx, 62
CMP rbx, 0
CMOVE rsi, rdx

# speculation
JMP rsi
.l1:
    # rbx = 0
    MOV rdx, [rcx]
    JMP .l3

.l2:
    # rbx != 0
    MOV rdx, [rcx + rax]
    JMP .l3
.l3:
MFENCE
