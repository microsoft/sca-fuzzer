.intel_syntax noprefix
.test_case_enter:
LEA R14, [R14 + 48] # instrumentation
MFENCE # instrumentation
.test_case_main:
.test_case_main.entry:
JMP .bb0
.bb0:
CMOVS AX, AX
REX CMP DL, 53
CMP EDX, 55
REX SETNLE AL
CMOVNL RCX, RCX
CMOVNP RAX, RAX
CMOVP CX, CX
SETS AL
MOVZX EBX, DL
ADC EAX, -2030331421
DEC RAX
AND RAX, 0b1111111000000 # instrumentation
ADD RAX, R14 # instrumentation
MOV CX, word ptr [RAX]
AND RAX, 0b1111111000000 # instrumentation
ADD RAX, R14 # instrumentation
LOCK SUB byte ptr [RAX], 110
AND RAX, 0b1111111000000 # instrumentation
ADD RAX, R14 # instrumentation
ADC AL, byte ptr [RAX]
AND RCX, 0b1111111000000 # instrumentation
ADD RCX, R14 # instrumentation
SUB EAX, dword ptr [RCX]
{store} XOR BL, BL
.test_case_main.exit:
.test_case_exit:
LEA R14, [R14 - 48] # instrumentation
MFENCE # instrumentation
