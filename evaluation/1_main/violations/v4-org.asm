.intel_syntax noprefix
.test_case_enter:
LEA R14, [R14 + 60] # instrumentation
MFENCE # instrumentation
.test_case_main:
.test_case_main.entry:
JMP .bb0
.bb0:
NOT EBX
{load} ADC BX, BX
AND RAX, 66
TEST BL, 22
CMP EAX, -26607054
{load} REX ADC CL, CL
CMOVBE RDX, RDX
CMOVO RAX, RAX
AND RCX, 0b0111111000000 # instrumentation
ADD RCX, R14 # instrumentation
CMP EBX, dword ptr [RCX]
AND RDX, 0b0111111000000 # instrumentation
ADD RDX, R14 # instrumentation
XCHG qword ptr [RDX], RDX
AND RAX, 0b0111111000000 # instrumentation
ADD RAX, R14 # instrumentation
MOVSX RBX, word ptr [RAX]
AND RBX, 0b0111111000000 # instrumentation
ADD RBX, R14 # instrumentation
ADC qword ptr [RBX], 18
SUB RBX, -1372851502
{store} ADC CL, CL
SBB RAX, -656812677
CMOVNZ RAX, RAX
{store} MOV ECX, ECX
{store} MOV DL, DL
AND RDX, 83
CLD
ADC RAX, 497487149
{load} REX SBB BL, BL
SETNZ BL
SETNZ AL
SBB RCX, 23
REX MOVZX RCX, CL
DEC EAX
{load} REX ADC AL, AL
CMOVNP RCX, RCX
AND RCX, 1169115132
LAHF
SBB EDX, -31
.test_case_main.exit:
.test_case_exit:
LEA R14, [R14 - 60] # instrumentation
MFENCE # instrumentation
