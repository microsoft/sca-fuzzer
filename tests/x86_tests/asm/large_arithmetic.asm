.intel_syntax noprefix
.section .data.main
mov rbx, 100
.l1:
lfence
lea rax, qword ptr [rax + rax + 8]
lea rax, qword ptr [rax + rax + 8]
lea rax, qword ptr [rax + rax + 8]
lea rax, qword ptr [rax + rax + 8]
lea rax, qword ptr [rax + rax + 8]
lea rax, qword ptr [rax + rax + 8]
lea rax, qword ptr [rax + rax + 8]
lea rax, qword ptr [rax + rax + 8]
lea rax, qword ptr [rax + rax + 8]
dec rbx
jnz .l1
.l2:

lfence

.test_case_exit:
