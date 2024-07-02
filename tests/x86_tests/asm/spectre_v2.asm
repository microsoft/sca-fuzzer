.intel_syntax noprefix
.test_case_enter:
.section .data.main

# reduce the entropy of rax
and rax, 0b111111000000

# prepare jump targets
lea rdx, qword ptr [rip + .l1]
lea rsi, qword ptr [rip + .l2]

# delay the jump
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax + 1]

# reduce the entropy in rbx
and rbx, 0b1000000

# select a target based on the random value in rbx
cmp rbx, 0
cmove rsi, rdx

jmp rsi   # misprediction
.l1:
    # rbx = 0
    mov rdx, qword ptr [r14 + rax]
.l2:
mfence

.test_case_exit:
