.intel_syntax noprefix
MFENCE # instrumentation
.test_case_enter:
.function_main:
.bb_main.entry:
JMP .bb_main.0 
.bb_main.0:
ADD SIL, -36 # instrumentation
JNLE .bb_main.1 
JMP .bb_main.3 
.bb_main.1:
ADD SIL, -65 # instrumentation
AND RSI, 0b1111111111111 # instrumentation
SETP byte ptr [R14 + RSI] 
ADD CL, CL 
TEST BL, SIL 
LOOP .bb_main.2 
JMP .bb_main.4 
.bb_main.2:
ADD DIL, -8 # instrumentation
AND RSI, 0b1111111111111 # instrumentation
BTS dword ptr [R14 + RSI], 0 
MOV EAX, -939380331 
CMOVZ RBX, RDI 
AND RAX, 0b1111111111111 # instrumentation
SBB DX, word ptr [R14 + RAX] 
SETNO SIL 
JLE .bb_main.3 
JMP .bb_main.exit 
.bb_main.3:
ADD DIL, 89 # instrumentation
CMOVLE EBX, ESI 
SETB BL 
AND RDX, 0b1111111111111 # instrumentation
AND DX, 0b111 # instrumentation
LOCK BTR word ptr [R14 + RDX], DX 
JMP .bb_main.4 
.bb_main.4:
AND RDI, 0b1111111111111 # instrumentation
XOR qword ptr [R14 + RDI], -26 
MOV AL, DL 
CMOVNP DI, DX 
NOT CL 
SETNL DL 
.bb_main.exit:
.test_case_exit:
MFENCE # instrumentation
