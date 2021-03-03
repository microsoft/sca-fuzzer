.intel_syntax noprefix
AND rax, 0b111111111111  # keep the mem. access within the sandbox

MOV rax, 62

MOV rbx, r14
ADD rbx, 63
MOV qword ptr [rbx], rax
CLFLUSH qword ptr [rbx]
MOV rax, 58
MFENCE

# put a value into store buffer; repeated several times to make sure we get a hit
MOV rcx, qword ptr [rbx]
CLFLUSH qword ptr [rbx]
LFENCE
MOV rcx, qword ptr [rbx]
CLFLUSH qword ptr [rbx]
LFENCE
MOV rcx, qword ptr [rbx]
CLFLUSH qword ptr [rbx]
LFENCE
MOV rcx, qword ptr [rbx]
CLFLUSH qword ptr [rbx]
LFENCE
MOV rcx, qword ptr [rbx]
CLFLUSH qword ptr [rbx]
LFENCE
MOV rcx, qword ptr [rbx]
CLFLUSH qword ptr [rbx]
LFENCE
MOV rcx, qword ptr [rbx]
CLFLUSH qword ptr [rbx]
LFENCE
MOV rcx, qword ptr [rbx]
CLFLUSH qword ptr [rbx]
LFENCE
MOV rcx, qword ptr [rbx]
CLFLUSH qword ptr [rbx]
LFENCE
MOV rcx, qword ptr [rbx]
CLFLUSH qword ptr [rbx]
LFENCE

MOV qword ptr [rbx], rax
SFENCE
MOV qword ptr [rbx], rax
SFENCE
MOV qword ptr [rbx], rax
SFENCE
MOV qword ptr [rbx], rax
SFENCE
MOV qword ptr [rbx], rax
SFENCE
MOV qword ptr [rbx], rax
SFENCE
MOV qword ptr [rbx], rax
SFENCE
MOV qword ptr [rbx], rax
SFENCE
MOV qword ptr [rbx], rax
SFENCE

MOV rcx, 0
MOV rdx, 0
#LEA rbx, [rbx + rcx + 1]
#LEA rbx, [rbx + rcx - 1]
#LEA rbx, [rbx + rcx + 1]
#LEA rbx, [rbx + rcx - 1]
#LEA rdx, [rdx + rcx + 1]
#LEA rdx, [rdx + rcx - 1]
LEA rdx, [rdx + rcx + 1]  # comment us to enable SB leakage
LEA rdx, [rdx + rcx - 1]  # comment us to enable SB leakage
LEA rdx, [rdx + rcx + 1]
LEA rdx, [rdx + rcx - 1]
MOV qword ptr [rbx + rdx], rax


# Read from a non-accessed address thus triggerring microcode assist
MOV rcx, [rbx + 4096]
SHL rcx, 6

# dependent load
#LFENCE
AND rcx, 0b111111000000
MOV rdx, [r14 + rcx]

MFENCE
