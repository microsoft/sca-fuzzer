.intel_syntax noprefix
LFENCE

AND rax, 0b111111000000  # keep the mem. access within the sandbox
AND rbx, 0b1  # reduce the range of values for rbx to {0,1}

CMP rbx, 0
JE .l1  # misprediction
    MOV rax, [r14 + rax]
.l1:
MFENCE
