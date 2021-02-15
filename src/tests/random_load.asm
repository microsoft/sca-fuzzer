.intel_syntax noprefix
# preserve base reg.
MOV rcx, r14

# get a rand value
IMUL edi, edi, 2891336453
ADD edi, 12345
MOV eax, edi

# get a page offset out of the rand value
SHL rax, 58
SHR rax, 52

# mem. access based on the offset
MOV rcx, [rcx + rax]
MFENCE
