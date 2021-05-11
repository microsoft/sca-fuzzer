.intel_syntax noprefix
.test_case_enter:
LEA R14, [R14 + 48] # instrumentation
MFENCE # instrumentation
.test_case_main:
.test_case_main.entry:
JMP .bb0
.bb0:
ADC EAX, -2030331421
AND RAX, 0b1111111000000 # instrumentation
ADD RAX, R14 # instrumentation
MOV CX, word ptr [RAX]
AND RCX, 0b1111111000000 # instrumentation
ADD RCX, R14 # instrumentation
SUB EAX, dword ptr [RCX]
LEA R14, [R14 - 48] # instrumentation
MFENCE # instrumentation