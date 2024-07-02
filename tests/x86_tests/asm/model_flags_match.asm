.intel_syntax noprefix
.test_case_enter:
.section .data.main
lfence
mov rax, r14

mov rbx, 0
mov rcx, 64
cmovb rbx, rcx
mov rcx, qword ptr [rax + rbx]

mov rbx, 0
mov rcx, 128
cmovbe rbx, rcx
mov rcx, qword ptr [rax + rbx]

mov rbx, 0
mov rcx, 192
cmovl rbx, rcx
mov rcx, qword ptr [rax + rbx]

mov rbx, 0
mov rcx, 256
cmovle rbx, rcx
mov rcx, qword ptr [rax + rbx]

mov rbx, 0
mov rcx, 320
cmovo rbx, rcx
mov rcx, qword ptr [rax + rbx]

mov rbx, 0
mov rcx, 384
cmovp rbx, rcx
mov rcx, qword ptr [rax + rbx]

mov rbx, 0
mov rcx, 448
cmovs rbx, rcx
mov rcx, qword ptr [rax + rbx]

mov rbx, 0
mov rcx, 512
cmovz rbx, rcx
mov rcx, qword ptr [rax + rbx]

// cmovnb
// cmovnbe
// cmovnl
// cmovnle
// cmovno
// cmovnp
// cmovns
// cmovnz
mfence
.test_case_exit:
