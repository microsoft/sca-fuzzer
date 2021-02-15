# This test case is identical to spectre_v1 except the offset of the speculative mem. access
# is input-independent. Therefore, this test case must not be flagged.

.intel_syntax noprefix
MOV rcx, r14

# input: ebx - a random value, eax - fixed value
MOV rax, 128
IMUL edi, edi, 2891336453
ADD edi, 12345
MOV ebx, edi
LFENCE

# no delay to increase the likelihood of a false positive
SHL rbx, 63
SHR rbx, 63

# speculation
CMP rbx, 0
JE .l1
    # rbx != 0
    MOV rcx, [rcx + rax]
JMP .l2
.l1:
    # rbx == 0
    MOV rcx, [rcx]
.l2:
MFENCE
