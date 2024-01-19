.intel_syntax noprefix
.test_case_enter:
lea r14, [r14 + 60] # instrumentation
mfence # instrumentation

.test_case_main:
.test_case_main.entry:
jmp .bb0
.bb0:
cmp ax, 26587
{store} sbb dx, dx

and rdx, 0b1111111000000 # instrumentation
mul qword ptr [r14 + rdx]

and rdx, 0b1111111000000 # instrumentation
sbb word ptr [r14 + rdx], -30645

lea r14, [r14 - 60] # instrumentation
mfence # instrumentation
