.intel_syntax noprefix
.test_case_enter:
.section .data.main
LFENCE
MOV rax, r14

MOV rbx, 0
MOV rcx, 64
CMOVB rbx, rcx
MOV rcx, qword ptr [rax + rbx]

MOV rbx, 0
MOV rcx, 128
CMOVBE rbx, rcx
MOV rcx, qword ptr [rax + rbx]

MOV rbx, 0
MOV rcx, 192
CMOVL rbx, rcx
MOV rcx, qword ptr [rax + rbx]

MOV rbx, 0
MOV rcx, 256
CMOVLE rbx, rcx
MOV rcx, qword ptr [rax + rbx]

MOV rbx, 0
MOV rcx, 320
CMOVO rbx, rcx
MOV rcx, qword ptr [rax + rbx]

MOV rbx, 0
MOV rcx, 384
CMOVP rbx, rcx
MOV rcx, qword ptr [rax + rbx]

MOV rbx, 0
MOV rcx, 448
CMOVS rbx, rcx
MOV rcx, qword ptr [rax + rbx]

MOV rbx, 0
MOV rcx, 512
CMOVZ rbx, rcx
MOV rcx, qword ptr [rax + rbx]

// CMOVNB
// CMOVNBE
// CMOVNL
// CMOVNLE
// CMOVNO
// CMOVNP
// CMOVNS
// CMOVNZ
MFENCE
.test_case_exit:
