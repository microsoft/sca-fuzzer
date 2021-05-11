.intel_syntax noprefix
.test_case_enter:
LEA R14, [R14 + 12] # instrumentation
MFENCE # instrumentation
.test_case_main:
.test_case_main.entry:
JMP .bb0
.bb0:
CMOVNL ECX, ECX
AND RBX, 0b0111111000000 # instrumentation
ADD RBX, R14 # instrumentation
ADC dword ptr [RBX], -67100032
NOT RAX
JP .bb1
JMP .test_case_main.exit
.bb1:
AND RBX, 1048197274
ADD AX, 5229
AND RCX, 0b0111111000000 # instrumentation
ADD RCX, R14 # instrumentation
LOCK ADC dword ptr [RCX], 115
{load} ADD RCX, RCX
{load} REX OR AL, AL
.test_case_main.exit:
.test_case_exit:
LEA R14, [R14 - 12] # instrumentation
MFENCE # instrumentation
