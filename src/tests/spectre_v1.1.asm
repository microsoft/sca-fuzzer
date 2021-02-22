.intel_syntax noprefix
LFENCE

# reduce the entropy of rax
AND rax, 0b111111000000

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
    MOV qword ptr [r14], rax
    MOV rbx, [r14]
    MOV rbx, [r14 + rbx]
.l1:
MFENCE
