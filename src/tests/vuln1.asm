.intel_syntax noprefix
.test_case_enter:
CALL test_case_main
JMP .test_case_exit
test_case_main:
.test_case_main.entry:
IMUL edi, edi, 2891336453
ADD edi, 12345
IMUL edi, edi, 2891336453
ADD edi, 12345
IMUL edi, edi, 2891336453
ADD edi, 12345
IMUL edi, edi, 2891336453
IMUL edi, edi, 2891336453
IMUL edi, edi, 2891336453

MOV eax, 1934040435
MOV ebx, 1051096184
MOV ecx, 3182403217
MOV edx, 3633890318
MOV esi, 1092623999
MOV r13d, 1094319540

LFENCE
.main.generated:
AND r13, 0b111111000000
ADD r13, r14
LOCK SUB word ptr [r13], -52
SBB r13w, 8
CMOVBE rax, rax
AND rbx, 0b111111000000
ADD rbx, r14
AND dword ptr [rbx], 2097993599
AND rdx, -6
XCHG rcx, RAX
AND rdx, 0b111111000000
ADD rdx, r14
MOV dword ptr [rdx], 528501967
SBB rax, 1590320252
AND r13, 0b111111000000
ADD r13, r14
CMP word ptr [r13], -19253
AND rsi, 0b111111000000
ADD rsi, r14
RCR dword ptr [rsi], 80
AND rsi, 0b111111000000
ADD rsi, r14
LOCK ADD qword ptr [rsi], -400522771
MOVSX DI, CL
REX SETNB dl
BSF esi, r13d
RCL rsi, 78
REX XOR bl, 65
AND rdx, 0b111111000000
ADD rdx, r14
OR qword ptr [rdx], 604677365
{store} OR r13w, cx
AND rdx, 0b111111000000
ADD rdx, r14
LOCK DEC word ptr [rdx]
AND rbx, 0b111111000000
ADD rbx, r14
CMOVP bx, word ptr [rbx]
AND r13, 0b111111000000
ADD r13, r14
SAR dword ptr [r13], 106
AND rdx, 0b111111000000
ADD rdx, r14
REX CMP byte ptr [rdx], bl
NOP
AND rcx, 0b111111000000
ADD rcx, r14
OR byte ptr [rcx], DL
SAR eax, -49
JMP .test_case_main.exit
.test_case_main.exit:
RET
.test_case_exit:
MFENCE
