.intel_syntax noprefix
.section .data.main
.function_main:
.bb_main.entry:
jmp .bb_main.0
.bb_main.0:
test dil, 51
adc ax, -49
xor eax, ecx
and rax, 0b1111111111111 # instrumentation
or ebx, dword ptr [r14 + rax]
or al, bl
and rsi, 0b1111111111111 # instrumentation
xor byte ptr [r14 + rsi], al
setl bl
xor ax, -2067
lea si, qword ptr [rsi + rbx]
sbb cl, cl
and rdx, 0b1111111111111 # instrumentation
lock and dword ptr [r14 + rdx], -37
dec al
test al, -117 # instrumentation
and rax, 0b1111111111111 # instrumentation
xchg qword ptr [r14 + rax], rcx
movsx esi, cl
xadd rdi, rdi
.bb_main.exit:
.test_case_exit:
