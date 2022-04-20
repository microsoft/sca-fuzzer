.intel_syntax noprefix
.test_case_enter:

AND rax, 0b111111000000 # instrumentation
AND rbx, 0b111111000000 # instrumentation
AND rcx, 0b111111000000 # instrumentation
AND rdx, 0b111111000000 # instrumentation
AND rsi, 0b111111000000 # instrumentation

JO .JO_o
.JO_i:
LFENCE
MOV qword ptr [r14 + rax], 1
.JO_o:

JS .JS_o
.JS_i:
LFENCE
MOV qword ptr [r14 + rbx], 1
.JS_o:

JZ .JZ_o
.JZ_i:
LFENCE
MOV qword ptr [r14 + rcx], 1
.JZ_o:

JB .JB_o
.JB_i:
LFENCE
MOV qword ptr [r14 + rdx], 1
.JB_o:

JP .JP_o
.JP_i:
LFENCE
MOV qword ptr [r14 + rsi], 1
.JP_o:

.test_case_exit:
