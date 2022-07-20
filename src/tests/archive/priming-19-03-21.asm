# This test case is an example where too large min_primer_size causes a false positive
# It happens because some measurements require a fresh state of the predictors to reproduce
.intel_syntax noprefix
.test_case_enter:
MFENCE
ADD R14, 41
test_case_main:
.test_case_main.entry:
JMP .bb0
.bb0:
CMOVNO RBX, RBX
AND RCX, 0b111111000000
ADD RCX, R14
CMOVZ ECX, dword ptr [RCX]
LAHF
{store} ADC RAX, RAX
AND RDX, 0b111111000000
ADD RDX, R14
SETNZ byte ptr [RDX]
MOVSX EDX, BX
AND RCX, 0b111111000000
ADD RCX, R14
CMOVNLE CX, word ptr [RCX]
SUB CX, 19187
JNP .bb1
JMP .bb2
.bb1:
CMOVS AX, AX
MOVZX EDX, CX
{store} SBB RAX, RAX
DEC AL
{store} ADC RBX, RBX
CMOVBE EAX, EAX
{load} OR DL, DL
SETB BL
{disp32} JS .bb2
JMP .bb3
.bb2:
AND RDX, 0b111111000000
ADD RDX, R14
ADD qword ptr [RDX], 621805592
AND RAX, 0b111111000000
ADD RAX, R14
SUB dword ptr [RAX], 1
ADD RBX, -17
SUB AX, -4468
{load} REX MOV DL, DL
ADD EBX, -46
AND RCX, 0b111111000000
ADD RCX, R14
MOV dword ptr [RCX], EAX
AND RCX, 0b111111000000
ADD RCX, R14
SETP byte ptr [RCX]
JMP .bb3
.bb3:
{store} OR RAX, RAX
CMOVNZ RDX, RDX
AND CL, -3
AND RBX, 0b111111000000
ADD RBX, R14
LOCK ADC word ptr [RBX], BX
REX SETNZ AL
TEST RAX, -931866672
ADD RAX, 289288668
{store} ADD AX, AX
JMP .test_case_main.exit
.test_case_main.exit:
.test_case_exit:
SUB R14, 41
MFENCE
