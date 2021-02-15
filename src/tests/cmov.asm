.intel_syntax noprefix
// this is just to keep prng state in synch with what our tools expect
IMUL EDI, EDI, 2891336453
ADD EDI, 12345
IMUL EDI, EDI, 2891336453
ADD EDI, 12345
IMUL EDI, EDI, 2891336453
ADD EDI, 12345
IMUL EDI, EDI, 2891336453
ADD EDI, 12345
IMUL EDI, EDI, 2891336453
ADD EDI, 12345
IMUL EDI, EDI, 2891336453
ADD EDI, 12345

// generate random eflags value
IMUL EDI, EDI, 2891336453
ADD EDI, 12345
ADD RSP, 8
PUSHQ RDI
AND qword ptr [RSP], 2263
OR qword ptr [RSP], 2
//MOV r10, qword ptr [RSP]
POPFQ
LEA RSP, [RSP - 8]

LFENCE
MOV rax, r14

MOV rbx, 0
MOV rcx, 64
CMOVB rbx, rcx
MOV rcx, [rax + rbx]

MOV rbx, 0
MOV rcx, 128
CMOVBE rbx, rcx
MOV rcx, [rax + rbx]

MOV rbx, 0
MOV rcx, 192
CMOVL rbx, rcx
MOV rcx, [rax + rbx]

MOV rbx, 0
MOV rcx, 256
CMOVLE rbx, rcx
MOV rcx, [rax + rbx]

MOV rbx, 0
MOV rcx, 320
CMOVO rbx, rcx
MOV rcx, [rax + rbx]

MOV rbx, 0
MOV rcx, 384
CMOVP rbx, rcx
MOV rcx, [rax + rbx]

MOV rbx, 0
MOV rcx, 448
CMOVS rbx, rcx
MOV rcx, [rax + rbx]

MOV rbx, 0
MOV rcx, 512
CMOVZ rbx, rcx
MOV rcx, [rax + rbx]

// CMOVNB
// CMOVNBE
// CMOVNL
// CMOVNLE
// CMOVNO
// CMOVNP
// CMOVNS
// CMOVNZ
