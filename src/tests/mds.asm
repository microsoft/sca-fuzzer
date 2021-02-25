.intel_syntax noprefix
AND rax, 0b111111111111  # keep the mem. access within the sandbox
#MOV rax, 46
MFENCE

# put a value into store buffer; repeated several times to make sure we get a hit
MOV qword ptr [r14], rax
MOV rax, qword ptr [r14]
SFENCE
MOV qword ptr [r14], rax
MOV rax, qword ptr [r14]
SFENCE
MOV qword ptr [r14], rax
MOV rax, qword ptr [r14]
SFENCE
MOV qword ptr [r14], rax
MOV rax, qword ptr [r14]
SFENCE
MOV qword ptr [r14], rax
MOV rax, qword ptr [r14]
SFENCE
MOV qword ptr [r14], rax
MOV rax, qword ptr [r14]
SFENCE
MOV qword ptr [r14], rax
MOV rax, qword ptr [r14]
SFENCE
MOV qword ptr [r14], rax
MOV rax, qword ptr [r14]
SFENCE

MOV qword ptr [r14], rax
MOV rax, qword ptr [r14]

# Read from a non-accessed address thus triggerring microcode assist
ADD rcx, [r14 + 4096]
SHL rcx, 6

# dependent load
#LFENCE
AND rcx, 0b111111000000
MOV rdx, [r14 + rcx]

MFENCE
