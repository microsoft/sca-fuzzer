.intel_syntax noprefix
.test_case_enter:
LEA R14, [R14 + 8] # instrumentation
MFENCE # instrumentation
.test_case_main:
.test_case_main.entry:
JMP .bb0
.bb0:
MOV RDX, 0 # leftover instrumentation
OR BX, 0x1c # leftover instrumentation
AND RAX, 0xff # leftover instrumentation
CMOVNZ BX, BX
AND RBX, 0b0111111000000 # leftover instrumentation
ADD RBX, R14 # leftover instrumentation
XOR AX, AX
AND RBX, 0b0111111000000 # instrumentation
ADD RBX, R14 # instrumentation
SETNS byte ptr [RBX]  # < ---------- delayed store
AND RAX, 0b0111111000000 # instrumentation
ADD RAX, R14 # instrumentation
MOVZX EDX, byte ptr [RAX]  # < ----- store bypass
AND RDX, 0b0111111000000 # instrumentation
ADD RDX, R14 # instrumentation
AND RCX, qword ptr [RDX]   # < ----- speculative leakage
LEA R14, [R14 - 8] # instrumentation
MFENCE # instrumentation
