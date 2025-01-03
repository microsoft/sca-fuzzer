.intel_syntax noprefix
.section .data.main

# speculative offset:
# these shifts generate a random page offset, 64-bit aligned
and rax, 0b111111000000
lfence

mov rcx, r14
add rsp, 8  # ensure that the call and ret use the first cache set

call .function_1

.unreachable:
// lfence  # if you uncomment this line, the speculation will stop
and rax, 0b110000000  # reduce the number of possibilities
mov rax, qword ptr [rcx + rax]  # speculative access
lfence

.function_1:
lea rdx, qword ptr [rip + .function_2]
mov qword ptr [rsp], rdx
ret

.function_2:
mov rdx, qword ptr [rcx + 64]
mfence

# clear to avoid failing the arch check
mov rcx, 0
mov rdx, 0

.test_case_exit:
