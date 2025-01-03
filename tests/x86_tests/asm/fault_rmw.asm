.intel_syntax noprefix
.section .data.main
xadd qword ptr [r14 + 4096], rax
add rax, rbx
and rax, 0b111111111111 # instrumentation
mov rax, qword ptr [r14 + rax + 128]
.test_case_exit:
