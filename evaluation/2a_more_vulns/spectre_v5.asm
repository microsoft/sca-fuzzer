.intel_syntax noprefix
AND rax, 0b111111000000  # keep the mem. access within the sandbox
MFENCE

ADD rsp, 8  # ensure that the CALL and RET use the first cache set

CALL f1

unreachable:
// LFENCE  # if you uncomment this line, the speculation will stop
MOV rax, [r14 + rax]  # speculative access
JMP f2
LFENCE

f1:
LEA rdx, [rip + f2]
MOV [rsp], rdx # overwrite the return address with f2
RET

f2:
MFENCE
