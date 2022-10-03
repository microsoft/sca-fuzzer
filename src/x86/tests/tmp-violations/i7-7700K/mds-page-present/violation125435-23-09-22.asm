.intel_syntax noprefix
MFENCE # instrumentation
.test_case_enter:
.function_main:
.bb_main.entry:
JMP .bb_main.0
.bb_main.0:
BTC RDX, 101
AND RDX, 0b1111111111111 # instrumentation
MOV EAX, dword ptr [R14 + RDX]
AND RCX, 0b1111111111111 # instrumentation
BTC dword ptr [R14 + RCX], 4
XCHG CL, CL
CWD
SUB EAX, EDX
AND RCX, 0b1111111111111 # instrumentation
MOV qword ptr [R14 + RCX], 1931045169
OR RAX, RDX
AND RDI, 0b1111111111111 # instrumentation
LOCK ADC word ptr [R14 + RDI], DX
SETBE AL
AND RDX, 0b1111111111111 # instrumentation
IMUL EBX, dword ptr [R14 + RDX], -10
NEG EAX
TEST RDX, RCX
XCHG AX, AX
AND RBX, 0b1111111111111 # instrumentation
CMOVNLE EDI, dword ptr [R14 + RBX]
AND RAX, 0b1111111111111 # instrumentation
ADD SI, word ptr [R14 + RAX]
.bb_main.exit:
.test_case_exit:
MFENCE # instrumentation
