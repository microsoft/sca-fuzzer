.intel_syntax noprefix
.test_case_enter:
.section .data.main
MOV rbx, 100
.l1:
LFENCE
LEA rax, qword ptr [rax + rax + 8]
LEA rax, qword ptr [rax + rax + 8]
LEA rax, qword ptr [rax + rax + 8]
LEA rax, qword ptr [rax + rax + 8]
LEA rax, qword ptr [rax + rax + 8]
LEA rax, qword ptr [rax + rax + 8]
LEA rax, qword ptr [rax + rax + 8]
LEA rax, qword ptr [rax + rax + 8]
LEA rax, qword ptr [rax + rax + 8]
DEC rbx
JNZ .l1
.l2:

LFENCE

.test_case_exit:
