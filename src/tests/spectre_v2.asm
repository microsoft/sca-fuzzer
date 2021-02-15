.intel_syntax noprefix
LFENCE

# reduce the entropy of rax
AND rax, 0b111111000000

# prepare jump targets
LEA rdx, [rip + .l1]
LEA rsi, [rip + .l2]

# delay the jump
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

# reduce the entropy in rbx
AND rbx, 0b1

# select a target based on the random value in rbx
CMP rbx, 0
CMOVE rsi, rdx

JMP rsi   # misprediction
.l1:
    # rbx = 0
    MOV rdx, [r14 + rax]
.l2:
MFENCE
