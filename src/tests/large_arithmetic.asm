.intel_syntax noprefix
.test_case_enter:
MOV rbx, 1000
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

LFENCE
