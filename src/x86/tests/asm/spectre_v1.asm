.intel_syntax noprefix
.test_case_enter:
.section .data.main
lfence

# reduce the entropy of rax
and rax, 0b111111000000

# delay the cond. jump
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

cmp rbx, 0
je .l1  # misprediction
.l0:
    # rbx != 0
    mov rax, qword ptr [r14 + rax]
jmp .l2
.l1:
    # rbx == 0
    #mov rax, qword ptr [r14 + 64]
.l2:
mfence

.test_case_exit:
