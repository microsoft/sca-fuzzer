.intel_syntax noprefix
MFENCE # instrumentation
.test_case_enter:
.function_main:
.bb_main.entry:
JMP .bb_main.0
.bb_main.0:
ADD SIL, -68 # instrumentation
INC DL
DEC DX
ADC BL, CL
SUB CL, CL
AND RDX, 0b1111111111111 # instrumentation
LOCK SUB word ptr [R14 + RDX], BX
BTS SI, DX
CMC
MOVZX RAX, DIL
AND RSI, 0b1111111111111 # instrumentation
IMUL RAX, qword ptr [R14 + RSI]
AND RBX, 0b1111111111111 # instrumentation
XOR byte ptr [R14 + RBX], DL
AND RAX, 0b1111111111111 # instrumentation
IMUL RAX, qword ptr [R14 + RAX]
AND RDI, 0b1111111111111 # instrumentation
OR byte ptr [R14 + RDI], DL
SETP CL
BSWAP EDX
AND RBX, 0b1111111111111 # instrumentation
CMOVLE EDX, dword ptr [R14 + RBX]
ADD RAX, -1344536761
.bb_main.exit:
.test_case_exit:
MFENCE # instrumentation
