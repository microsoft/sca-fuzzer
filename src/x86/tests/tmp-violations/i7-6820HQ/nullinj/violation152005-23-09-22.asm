.intel_syntax noprefix
MFENCE # instrumentation
.test_case_enter:
.function_main:
.bb_main.entry:
JMP .bb_main.0
.bb_main.0:
OR DL, BL
XCHG RSI, RCX
SUB AX, -31639
AND RAX, 0b1111111111111 # instrumentation
OR dword ptr [R14 + RAX], 0b1000000000000000000000000000000 # instrumentation
BSR EDI, dword ptr [R14 + RAX]
SUB AX, -32250
SUB DL, DL
SETL DL
AND RSI, 0b1111111111111 # instrumentation
ADD EDI, dword ptr [R14 + RSI]
NEG RBX
OR AX, -8880
XOR AL, -41
SETL AL
CWD
CLC
NEG EDX
AND RDX, 0b1111111111111 # instrumentation
CMP DL, byte ptr [R14 + RDX]
.bb_main.exit:
.test_case_exit:
MFENCE # instrumentation
