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
{store} ADC DX, DX
BSWAP RAX
JMP .bb1
.bb1:
{store} XOR RDX, RDX
REX MOVZX RAX, DL
AND RBX, 0b1111111000000 # instrumentation
ADD RBX, R14 # instrumentation
OR dword ptr [RBX], -1193072838
NEG RDX
.test_case_main.exit:
.test_case_exit:
LEA R14, [R14 - 8] # instrumentation
MFENCE # instrumentation
