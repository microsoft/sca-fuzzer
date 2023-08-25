.intel_syntax noprefix
.test_case_enter:
.section .data.0_host

# reduce the entropy of rax
AND rax, 0b111111000000

# prepare jump targets
LEA rdx, qword ptr [rip + .l1]
LEA rsi, qword ptr [rip + .l2]

# delay the jump
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

# select a target based on the random value in rbx
CMP rbx, 0
CMOVE rsi, rdx

JMP rsi   # misprediction
.l1:
    # rbx = 0
    MOV rdx, qword ptr [r14 + rax]
.l2:
MFENCE
