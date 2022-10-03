.intel_syntax noprefix
MFENCE # instrumentation
.test_case_enter:
.function_main:
.bb_main.entry:
JMP .bb_main.0
.bb_main.0:
OR ECX, -87
DEC DI
MOVZX EAX, SI
BTR DI, -24
CMP RBX, RBX
BTR AX, 90
SUB RSI, -41
OR RCX, RDX
ADD EDI, 100
AND RAX, 0b1111111111111 # instrumentation
SBB dword ptr [R14 + RAX], -115
ADC RAX, -18
AND RCX, 0b111111111111 # instrumentation
CMOVNB ECX, dword ptr [R14 + RCX]
AND RCX, 0b111111111111 # instrumentation
SBB EDI, dword ptr [R14 + RCX]
CMOVNB RSI, RDX
MOV BL, 91
AND RBX, 0b111111111111 # instrumentation
CMOVB DI, word ptr [R14 + RBX]
.bb_main.exit:
.test_case_exit:
MFENCE # instrumentation
