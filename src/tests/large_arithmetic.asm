.intel_syntax noprefix
MOV rbx, 1000
.l1:
LFENCE
LEA rax, [rax + rax + 8]
LEA rax, [rax + rax + 8]
LEA rax, [rax + rax + 8]
LEA rax, [rax + rax + 8]
LEA rax, [rax + rax + 8]
LEA rax, [rax + rax + 8]
LEA rax, [rax + rax + 8]
LEA rax, [rax + rax + 8]
LEA rax, [rax + rax + 8]
DEC rbx
JNZ .l1

LFENCE
