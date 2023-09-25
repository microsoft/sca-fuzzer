.intel_syntax noprefix
.test_case_enter:
.section .data.0_host
.function_main:
.bb_main.entry:
JMP .bb_main.0
.bb_main.0:
TEST DIL, 51
ADC AX, -49
XOR EAX, ECX
AND RAX, 0b1111111111111 # instrumentation
OR EBX, dword ptr [R14 + RAX]
OR AL, BL
AND RSI, 0b1111111111111 # instrumentation
XOR byte ptr [R14 + RSI], AL
SETL BL
XOR AX, -2067
LEA SI, qword ptr [RSI + RBX]
SBB CL, CL
AND RDX, 0b1111111111111 # instrumentation
LOCK AND dword ptr [R14 + RDX], -37
DEC AL
TEST AL, -117 # instrumentation
AND RAX, 0b1111111111111 # instrumentation
XCHG qword ptr [R14 + RAX], RCX
MOVSX ESI, CL
XADD RDI, RDI
.bb_main.exit:
.test_case_exit:
