.intel_syntax noprefix
.test_case_enter:

# accumulate base address into rax
ADD rax, r14

# sample several addresses from each region and accumulate in rax
ADD rax, qword ptr [r14]
ADD rax, qword ptr [r14 + 4096]
ADD rax, qword ptr [r14 + 4096 - 8]
ADD rax, qword ptr [r14 + 8192]  # register init region
ADD rax, qword ptr [r14 + 8192 + 48] # flags init value
.test_case_exit:
