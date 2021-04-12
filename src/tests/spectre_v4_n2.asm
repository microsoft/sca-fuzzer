.intel_syntax noprefix
MOV rax, 0

# the leaked value - rcx
# construct a page offset from the random value
AND rcx, 0b111111000000
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
AND rbx, 0b111000000
SHR rbx, 3

# store and load, potentially matching
MOV qword ptr  [r14 + rbx], 4096 - 64
MOV qword ptr  [r14 + rbx], 4096 - 64
MOV rdx, [r14]  # misprediction happens here

# dependent load
MOV rdx, [r14 + rdx]
MFENCE
