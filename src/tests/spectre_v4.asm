.intel_syntax noprefix
MOV rax, 0

# the leaked value - rcx
# construct a page offset from the random value
SHL rcx, 58
SHR rcx, 58
SHL rcx, 6
ADD rcx, 64

# save some value into the test address
MOV qword ptr [r14], rcx
MFENCE

# delay the store
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
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]
LEA rbx, [rbx + rax + 1]

# select the store address based on the random value
# the likelihood of the match must be relatively low, otherwise the predictor won't kick in
# at least 1/8 runs
SHL rbx, 61
SHR rbx, 61
SHL rbx, 3 # multiply by 8 to avoid collisions with the load

# store and load, potentially matching
MOV qword ptr  [r14 + rbx], 4096 - 64
MOV rdx, [r14]  # misprediction happens here

# dependent load
MOV rdx, [r14 + rdx]
MFENCE
