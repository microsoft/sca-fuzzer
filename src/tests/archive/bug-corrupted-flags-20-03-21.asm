.intel_syntax noprefix
.test_case_enter:
mfence
add r14, 59
test_case_main:
.test_case_main.entry:
jmp .bb0
.bb0:
lfence
{store} rex or dl, dl
lfence
and al, 61
lfence
{disp32} jno .bb1
lfence
jmp .bb2
lfence
.bb1:
lfence
lahf
lfence
and rbx, 0b111111000000
lfence
add rbx, r14
lfence
.bb2:
lfence
and rdx, 0b111111000000
lfence
add rdx, r14
lfence
and rcx, 0b111111000000
lfence
add rcx, r14
lfence
and rcx, 0b111111000000
lfence
add rcx, r14
lfence
and rcx, 0b111111000000
lfence
add rcx, r14
lfence
and rax, 0b111111000000
lfence
add rax, r14
lfence
lock sbb byte ptr [rax], bl
sub r14, 59
