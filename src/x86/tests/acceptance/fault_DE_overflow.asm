.intel_syntax noprefix
.test_case_enter:

ADD ebx, 1
LFENCE
DIV bx
# MOV rcx, rax

# # encode bits 0:5
# SHL rcx, 6
# AND rcx, 0b111111000000 # instrumentation
# MOV rdx, qword ptr [r14 + rcx]

# # encode bits 6:11
# AND rax, 0b111111000000 # instrumentation
# MOV rdx, qword ptr [r14 + rax]

MOV rbx, qword ptr [r14]
.test_case_exit:
