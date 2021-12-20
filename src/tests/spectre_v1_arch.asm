.intel_syntax noprefix
LFENCE

# delay the cond. jump
MOV rax, 0
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax - 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax - 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax - 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax - 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax - 1]

# reduce the entropy in rbx
AND rbx, 0b1000000

CMP rbx, 0
JE .l1  # misprediction
    # rbx != 0
    MOV rax, [r14 + 1024]
    SHL rax, 2
    AND rax, 0b111111000000
    MOV rax, [r14 + rax] # leakage happens here
.l1:

MFENCE
