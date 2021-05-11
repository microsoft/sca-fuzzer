.intel_syntax noprefix
.test_case_enter:
LEA R14, [R14 + 28] # instrumentation
MFENCE
JMP .bb0
.bb0:
NOP
NOP
CDQ
SETZ CL
ADD EDX, 117
REX ADD BL, BL
SETNLE AL
SUB RBX, RBX
TEST AL, 29
MOV RDX, 0 # instrumentation
OR RBX, 0x6d # instrumentation
AND RAX, 0xff # instrumentation
DIV RBX
{disp32} JNO .bb1
.bb1:
AND RCX, 0b111111000000 # instrumentation
ADD RCX, R14 # instrumentation
MOVZX EDX, byte ptr [RCX]
AND RAX, RAX
AND RAX, 0b111111000000 # instrumentation
ADD RAX, R14 # instrumentation
SBB qword ptr [RAX], 39412116
TEST ECX, ECX
AND RAX, 0b111111000000 # instrumentation
ADD RAX, R14 # instrumentation
MOV qword ptr [RAX], 81640764
REX NEG AL
CMC
OR RDX, 37323177
JNP .bb2
JMP .test_case_main.exit
.bb2:
REX SBB AL, AL
SBB EAX, 74935583
AND RDX, 0b111111000000 # instrumentation
ADD RDX, R14 # instrumentation
CMOVS RDX, qword ptr [RDX]
AND RAX, 0b111111000000 # instrumentation
ADD RAX, R14 # instrumentation
MOV qword ptr [RAX], 23088010
AND RBX, 0b111111000000 # instrumentation
ADD RBX, R14 # instrumentation
LOCK AND word ptr [RBX], 5518
.test_case_main.exit:
.test_case_exit:
LEA R14, [R14 - 28] # instrumentation
MFENCE # instrumentation
