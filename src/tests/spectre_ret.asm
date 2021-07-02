.intel_syntax noprefix

# speculative offset:
# these shifts generate a random page offset, 64-bit aligned
AND rax, 0b111111000000
LFENCE

MOV rcx, r14
ADD rsp, 8  # ensure that the CALL and RET use the first cache set

CALL f1

unreachable:
// LFENCE  # if you uncomment this line, the speculation will stop
AND rax, 0b110000000  # reduce the number of possibilities
MOV rax, [rcx + rax]  # speculative access
LFENCE

f1:
LEA rdx, [rip + f2]
MOV [rsp], rdx
RET

f2:
MOV rdx, [rcx + 64]
MFENCE
