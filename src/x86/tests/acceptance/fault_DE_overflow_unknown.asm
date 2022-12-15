.intel_syntax noprefix
.test_case_enter:

# # avoid div-by-zero
ADD ebx, 1# 
DIV ebx

# ADD rax, 1
# # leak 6 least significant bits of rax (result)
SHL rax, 6
AND rdx, 0b011111000000
AND rax, 0b011111000000 # instrumentation
MOV rsi, qword ptr [r14 + rdx]
MOV rsi, qword ptr [r14 + rax]
MOV rsi, qword ptr [r14 + 128 + rdx]
MOV rsi, qword ptr [r14 + 64 + rax]

# # leak 6 least significant bits of rdx (remainder)








# # leak more bits of rax (result)
# AND rbx, 0b111111000000 # instrumentation
# MOV rsi, qword ptr [r14 + rbx]

# # leak more bits of rdx (remainder)
# AND rcx, 0b111111000000 # instrumentation
# MOV rsi, qword ptr [r14 + rcx]

.test_case_exit:
