.intel_syntax noprefix

# test register values
SHL rax, 58
SHR rax, 52
MOV rax, [r14 + rax]

SHL rbx, 58
SHR rbx, 52
MOV rbx, [r14 + rbx]

SHL rcx, 58
SHR rcx, 52
MOV rcx, [r14 + rcx]

SHL rdx, 58
SHR rdx, 52
MOV rdx, [r14 + rdx]

MOV rax, rdi
SHL rax, 58
SHR rax, 52
MOV rax, [r14 + rax]

# test values in memory
MOV rax, [r14 + 1024]  # grab some from the "heap"
SHL rax, 58
SHR rax, 52
MOV rax, [r14 + rax]

MOV rax, [rsp + 1024]  # grab some from the "stack"
SHL rax, 58
SHR rax, 52
MOV rax, [r14 + rax]

MFENCE
