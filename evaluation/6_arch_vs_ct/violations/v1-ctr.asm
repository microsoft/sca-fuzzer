.intel_syntax noprefix
.test_case_enter:
LEA R14, [R14 + 4] # instrumentation
MFENCE # instrumentation
.test_case_main:
.test_case_main.entry:
JMP .bb0
.bb0:
{store} ADC CX, CX
AND RAX, 0b0111111000000 # instrumentation
ADD RAX, R14 # instrumentation
CMOVNS EBX, dword ptr [RAX]
AND RCX, 0b0111111000000 # instrumentation
ADD RCX, R14 # instrumentation
MOVZX ECX, byte ptr [RCX]
SUB RBX, 20
{store} ADC EDX, EDX
REX SETNLE AL
{store} REX ADC BL, BL
{disp32} JBE .bb1
JMP .test_case_main.exit
.bb1:
REX INC AL
AND RCX, 0b0111111000000 # instrumentation
ADD RCX, R14 # instrumentation
MOV EBX, dword ptr [RCX]
LFENCE
.test_case_main.exit:
LEA R14, [R14 - 4] # instrumentation
MFENCE # instrumentation