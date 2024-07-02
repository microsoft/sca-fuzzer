.intel_syntax noprefix
.test_case_enter:
.section .data.main
lfence

# reduce the entropy of rax
and rax, 0b111111000000

# delay the cond. jump
mov rcx, 0
lea rbx, qword ptr [rbx + rcx + 1]
lea rbx, qword ptr [rbx + rcx - 1]
lea rbx, qword ptr [rbx + rcx + 1]
lea rbx, qword ptr [rbx + rcx - 1]
lea rbx, qword ptr [rbx + rcx + 1]
lea rbx, qword ptr [rbx + rcx - 1]
lea rbx, qword ptr [rbx + rcx + 1]
lea rbx, qword ptr [rbx + rcx - 1]
lea rbx, qword ptr [rbx + rcx + 1]
lea rbx, qword ptr [rbx + rcx - 1]
lea rbx, qword ptr [rbx + rcx + 1]
lea rbx, qword ptr [rbx + rcx - 1]
lea rbx, qword ptr [rbx + rcx + 1]
lea rbx, qword ptr [rbx + rcx - 1]
lea rbx, qword ptr [rbx + rcx + 1]
lea rbx, qword ptr [rbx + rcx - 1]
lea rbx, qword ptr [rbx + rcx + 1]
lea rbx, qword ptr [rbx + rcx - 1]
lea rbx, qword ptr [rbx + rcx + 1]
lea rbx, qword ptr [rbx + rcx - 1]
lea rbx, qword ptr [rbx + rcx + 1]
lea rbx, qword ptr [rbx + rcx - 1]
lea rbx, qword ptr [rbx + rcx + 1]
lea rbx, qword ptr [rbx + rcx - 1]
lea rbx, qword ptr [rbx + rcx + 1]
lea rbx, qword ptr [rbx + rcx - 1]
lea rbx, qword ptr [rbx + rcx + 1]
lea rbx, qword ptr [rbx + rcx - 1]
lea rbx, qword ptr [rbx + rcx + 1]
lea rbx, qword ptr [rbx + rcx - 1]

# reduce the entropy in rbx
and rbx, 0b1

cmp rbx, 0
je .l1  # misprediction
.l0:
    # rbx != 0
    mov qword ptr [r14], rax
    mov rdx, qword ptr [r14]
    mov rbx, qword ptr [r14 + rdx]
.l1:
mfence

.test_case_exit:
