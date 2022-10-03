.intel_syntax noprefix
MFENCE # instrumentation
.test_case_enter:
.function_main:
.bb_main.entry:
JMP .bb_main.0
.bb_main.0:
ADD SIL, -61 # instrumentation
SETBE SIL
MOVZX ECX, AL
INC DL
CMOVNLE RCX, RCX
TEST RAX, -1441395001
CMOVNL SI, BX
IMUL CL
BT DI, -115
AND SIL, 20
CMOVB RBX, RDX
SUB CX, -29
MOV BL, -31
AND RAX, 0b1111111111111 # instrumentation
CMOVNLE RSI, qword ptr [R14 + RAX]
SBB DI, DX
AND RSI, 0b1111111111111 # instrumentation
OR dword ptr [R14 + RSI], 0b1000000000000000000000000000000 # instrumentation
BSR EBX, dword ptr [R14 + RSI]
AND RDI, -20
.bb_main.exit:
.test_case_exit:
MFENCE # instrumentation
