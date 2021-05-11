.intel_syntax noprefix
LFENCE

AND rax, 0b111111000000  # keep the mem. access within the sandbox
AND rbx, 0b1  # reduce the range of values for rbx to {0,1}

# prepare jump targets
LEA rdx, [rip + .l1]
LEA rsi, [rip + .l2]

CMP rbx, 0
CMOVE rsi, rdx

CMP rbx, 0
JMP rsi # misprediction
.l1:
    MOV rax, [r14 + rax]
.l2:
MFENCE
