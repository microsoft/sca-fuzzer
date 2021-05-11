.intel_syntax noprefix
.test_case_enter:
LEA R14, [R14 + 4] # instrumentation
MFENCE # instrumentation
.test_case_main:
.test_case_main.entry:
JMP .bb0
.bb0:
STC
AND EDX, 95
{store} ADC CX, CX
CMP EAX, -67
AND RAX, 0b0111111000000 # instrumentation
ADD RAX, R14 # instrumentation
CMOVNS EBX, dword ptr [RAX]
AND RCX, 0b0111111000000 # instrumentation
ADD RCX, R14 # instrumentation
MOVZX ECX, byte ptr [RCX]
SUB RBX, 20
{load} REX AND DL, DL
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
AND RCX, 0b0111111000000 # instrumentation
ADD RCX, R14 # instrumentation
CMOVNBE EAX, dword ptr [RCX]
CMOVNS RDX, RDX
{load} MOV AX, AX
{store} ADD AL, AL
AND RAX, 0b0111111000000 # instrumentation
ADD RAX, R14 # instrumentation
SBB byte ptr [RAX], 21
OR RAX, -1822275467
AND RBX, 0b0111111000000 # instrumentation
ADD RBX, R14 # instrumentation
SBB word ptr [RBX], BX
{load} ADD RDX, RDX
CMP EAX, 475869260
SETNLE CL
CLD
.test_case_main.exit:
.test_case_exit:
LEA R14, [R14 - 4] # instrumentation
MFENCE # instrumentation
