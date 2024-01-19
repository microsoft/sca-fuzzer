.intel_syntax noprefix
.test_case_enter:
mfence # instrumentation

and rbx, 0b0111111000000 # instrumentation
cmpxchg8b qword ptr [r14 + rbx]

mfence # instrumentation
