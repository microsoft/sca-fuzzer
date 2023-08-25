.intel_syntax noprefix
.test_case_enter:
.section .data.0_host
XADD qword ptr [r14 + 4096], rax
ADD rax, rbx
AND rax, 0b111111111111 # instrumentation
MOV rax, qword ptr [r14 + rax + 128]
.test_case_exit:
