.intel_syntax noprefix
LFENCE

AND rax, 0b111111000000  # keep the mem. access within the sandbox

# delay the cond. jump
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]

AND rbx, 0b1  # reduce the range of values for rbx to {0,1}

CMP rbx, 0
JE .l1  # misprediction
    MOV qword ptr [r14], rax
    MOV rbx, [r14]
    MOV rbx, [r14 + rbx]
.l1:
MFENCE
