.intel_syntax noprefix
MFENCE # instrumentation
.test_case_enter:
.function_main:
.bb_main.entry:
JMP .bb_main.0
.bb_main.0:
BTC BX, DI
ADD DIL, -100 # instrumentation
CMOVS RBX, RCX
TEST DIL, SIL
TEST BL, BL
TEST SI, AX
SETS DL
MOVZX RBX, DI
SBB CL, 60
MOVSX EBX, DX
XCHG ESI, EAX
OR ESI, -70
AND RSI, 0b1111111111111 # instrumentation
MOV AX, word ptr [R14 + RSI]
AND RAX, 0b1111111111111 # instrumentation
OR RBX, qword ptr [R14 + RAX]
MOVSX EDX, SI
ADD RAX, -2128649739
CMP RDX, RCX
.bb_main.exit:
.test_case_exit:
MFENCE # instrumentation
