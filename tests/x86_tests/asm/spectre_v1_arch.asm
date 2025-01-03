.intel_syntax noprefix
.section .data.main
lfence

# delay the cond. jump
mov rax, 0
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]

# reduce the entropy in rbx
and rbx, 0b1000000

cmp rbx, 0
je .l1  # misprediction
.l0:
    # rbx != 0
    mov rax, qword ptr [r14 + 1024]
    shl rax, 2
    and rax, 0b111111000000
    mov rax, qword ptr [r14 + rax] # leakage happens here
.l1:

mfence

.test_case_exit:
