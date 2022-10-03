.intel_syntax noprefix
MFENCE # instrumentation
.test_case_enter:
.function_main:
.bb_main.entry:
.bb_main.0:
OR EAX, -108815685
CMOVNBE RSI, RAX
AND RSI, 0b1111111111111 # instrumentation
XCHG dword ptr [R14 + RSI], ECX
XCHG CX, AX
AND RAX, 0b111111111111 # instrumentation
MOV AX, word ptr [R14 + RAX]
.bb_main.exit:
.test_case_exit:
MFENCE # instrumentation
