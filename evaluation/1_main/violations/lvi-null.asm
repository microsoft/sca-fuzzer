.intel_syntax noprefix
.test_case_enter:
LEA R14, [R14 + 8] # instrumentation
MFENCE # instrumentation
.test_case_main:
.test_case_main.entry:
JMP .bb0
.bb0:
SUB AX, 27095
AND RAX, 0b1111111000000 # instrumentation
ADD RAX, R14 # instrumentation
ADD BL, byte ptr [RAX]
AND RBX, 0b1111111000000 # instrumentation
ADD RBX, R14 # instrumentation
OR dword ptr [RBX], -1193072838
LEA R14, [R14 - 8] # instrumentation
MFENCE # instrumentation
