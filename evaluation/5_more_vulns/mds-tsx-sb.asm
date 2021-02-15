.intel_syntax noprefix

# write a page offset into Store Buffer
IMUL edi, edi, 2891336453
ADD edi, 12345
MOV ecx, edi
MFENCE

# put a value into store buffer
MOV qword ptr [r14], rcx
MOV rcx, qword ptr [r14]

# delay to allow data reach SB
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]


# Read from a non-accessed address thus triggerring microcode assist
XBEGIN .l1
MOV rcx, qword ptr [r14+4096]
AND rcx, 0b111111111111
XEND

.l1:

# dependent load
MOV rdx, [r14 + rcx]
MFENCE
