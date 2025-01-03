.intel_syntax noprefix
.section .data.main

mov rax, qword ptr [r14]  # main page
add rax, qword ptr [r14 + 4096]  # faulty page

mov rbx, qword ptr [r14 - 8]  # underflow pad
add rbx, qword ptr [r14 + 4096 + 4096 + 320]  # overflow pad

mov rcx, qword ptr [r14 + 4096 + 4096]  # reg init
mov rdx, qword ptr [r14 + 4096 + 4096 + 48]  # patched flags
mov rsi, qword ptr [r14 + 4096 + 4096 + 64]  # simd init
mov rdi, r14


# uncomment the following to test the complete sandbox contents
# xor rax, rax
# xor rbx, rbx
# xor rcx, rcx
# xor rdx, rcx
# mov rdi, 0xff8
# .l1:
# add rax, qword ptr [r14 + rdi]
# add rbx, qword ptr [r14 + rdi + 0x1000]
# add rcx, qword ptr [r14 + rdi + 0x2000]
# sub rdi, 8
# jnz .l1
# .l1_exit:

# mov rdi, 0xef8
# .l2:
# add rdx, qword ptr [r14 + rdi - 0xf00]
# sub rdi, 8
# jnz .l2

.test_case_exit:
