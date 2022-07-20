.intel_syntax noprefix
.test_case_enter:
MFENCE # instrumentation

AND RBX, 0b0111111000000 # instrumentation
CMPXCHG8B qword ptr [R14 + RBX]

MFENCE # instrumentation
