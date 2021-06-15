.intel_syntax noprefix
.test_case_enter:
LEA R14, [R14 + 60] # instrumentation
MFENCE # instrumentation

.test_case_main:
.test_case_main.entry:
JMP .bb0
.bb0:
CMP AX, 26587
{store} SBB DX, DX

AND RDX, 0b1111111000000 # instrumentation
MUL qword ptr [R14 + RDX]

AND RDX, 0b1111111000000 # instrumentation
SBB word ptr [R14 + RDX], -30645

LEA R14, [R14 - 60] # instrumentation
MFENCE # instrumentation
