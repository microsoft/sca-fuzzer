.intel_syntax noprefix

# random input - rax
IMUL edi, edi, 2891336453
ADD edi, 12345
MOV eax, edi

# speculative offset:
# these shifts generate a random page offset, 64-bit aligned
SHL rax, 58
SHR rax, 52
LFENCE

MOV rcx, r14
ADD rsp, 8  # ensure that the CALL and RET use the first cache set

CALL f1

unreachable:
// LFENCE  # if you uncomment this line, the speculation will stop
MOV rax, [rcx + rax]  # speculative access
LFENCE

f1:
LEA rdx, [rip + f2]
MOV [rsp], rdx
RET

f2:
MOV rdx, [rcx]
MFENCE
