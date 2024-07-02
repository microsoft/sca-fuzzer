.intel_syntax noprefix
.test_case_enter:
.section .data.main
and rax, 0b111111111111  # keep the mem. access within the sandbox
#mov rax, 46
mfence

# put a value into store buffer; repeated several times to make sure we get a hit
mov qword ptr [r14], rax
mov rax, qword ptr [r14]
sfence
mov qword ptr [r14], rax
mov rax, qword ptr [r14]
sfence
mov qword ptr [r14], rax
mov rax, qword ptr [r14]
sfence
mov qword ptr [r14], rax
mov rax, qword ptr [r14]
sfence
mov qword ptr [r14], rax
mov rax, qword ptr [r14]
sfence
mov qword ptr [r14], rax
mov rax, qword ptr [r14]
sfence
mov qword ptr [r14], rax
mov rax, qword ptr [r14]
sfence
mov qword ptr [r14], rax
mov rax, qword ptr [r14]
sfence

mov qword ptr [r14], rax
mov rax, qword ptr [r14]

# read from a non-accessed address thus triggerring microcode assist
add rcx, qword ptr [r14 + 4096]
//shl rcx, 6

# dependent load
#lfence
and rcx, 0b111111000000
mov rdx, qword ptr [r14 + rcx]

mfence

.test_case_exit:
