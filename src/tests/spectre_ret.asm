.intel_syntax noprefix
.test_case_enter:

# speculative offset:
# these shifts generate a random page offset, 64-bit aligned
AND rax, 0b111111000000
LFENCE

MOV rcx, r14
ADD rsp, 8  # ensure that the CALL and RET use the first cache set

CALL .function_1

.unreachable:
// LFENCE  # if you uncomment this line, the speculation will stop
AND rax, 0b110000000  # reduce the number of possibilities
MOV rax, qword ptr [rcx + rax]  # speculative access
LFENCE

.function_1:
LEA rdx, qword ptr [rip + .function_2]
MOV qword ptr [rsp], rdx
RET

.function_2:
MOV rdx, qword ptr [rcx + 64]
MFENCE
