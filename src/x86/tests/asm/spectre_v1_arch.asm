.intel_syntax noprefix
.test_case_enter:
.section .data.main
LFENCE

# delay the cond. jump
MOV rax, 0
LEA rbx, qword ptr [rbx + rax + 1]
LEA rbx, qword ptr [rbx + rax - 1]
LEA rbx, qword ptr [rbx + rax + 1]
LEA rbx, qword ptr [rbx + rax - 1]
LEA rbx, qword ptr [rbx + rax + 1]
LEA rbx, qword ptr [rbx + rax - 1]
LEA rbx, qword ptr [rbx + rax + 1]
LEA rbx, qword ptr [rbx + rax - 1]
LEA rbx, qword ptr [rbx + rax + 1]
LEA rbx, qword ptr [rbx + rax - 1]
LEA rbx, qword ptr [rbx + rax + 1]
LEA rbx, qword ptr [rbx + rax - 1]
LEA rbx, qword ptr [rbx + rax + 1]
LEA rbx, qword ptr [rbx + rax - 1]

# reduce the entropy in rbx
AND rbx, 0b1000000

CMP rbx, 0
JE .l1  # misprediction
.l0:
    # rbx != 0
    MOV rax, qword ptr [r14 + 1024]
    SHL rax, 2
    AND rax, 0b111111000000
    MOV rax, qword ptr [r14 + rax] # leakage happens here
.l1:

MFENCE

.test_case_exit:
