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

# reduce the entropy in rbx
AND rbx, 0b1

CMP rbx, 0
JE .l1  # misprediction
    # rbx != 0
    MOV rax, [r14]
    SHL rax, 8
    AND rax, 0b111111000000
    MOV rax, [r14 + rax + 128] # leakage happens here
.l1:

MFENCE
