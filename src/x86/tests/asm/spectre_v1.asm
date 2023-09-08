.intel_syntax noprefix
.test_case_enter:
.section .data.0_host
LFENCE

# reduce the entropy of rax
AND rax, 0b111111000000

# delay the cond. jump
LEA rbx, qword ptr [rbx + rax + 1]
LEA rbx, qword ptr [rbx + rax + 1]
LEA rbx, qword ptr [rbx + rax + 1]
LEA rbx, qword ptr [rbx + rax + 1]
LEA rbx, qword ptr [rbx + rax + 1]
LEA rbx, qword ptr [rbx + rax + 1]
LEA rbx, qword ptr [rbx + rax + 1]
LEA rbx, qword ptr [rbx + rax + 1]
LEA rbx, qword ptr [rbx + rax + 1]
LEA rbx, qword ptr [rbx + rax + 1]

# reduce the entropy in rbx
AND rbx, 0b1000000

CMP rbx, 0
JE .l1  # misprediction
.l0:
    # rbx != 0
    MOV rax, qword ptr [r14 + rax]
JMP .l2
.l1:
    # rbx == 0
    #MOV rax, qword ptr [r14 + 64]
.l2:
MFENCE

.test_case_exit:
