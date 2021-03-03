.intel_syntax noprefix

AND rax, 0b111111000000  # keep the mem. access within the sandbox
MOV qword ptr [r14], rax # put RAX into Store Buffer
MOV rax, 0
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


AND rbx, 0b111  # reduce the range of values for rbx to 0--7
SHL rbx, 3 # multiply by 8 to avoid collisions with the load

MOV qword ptr  [r14 + rbx], 0 # store some new value
MOV rdx, [r14]  # a load, potentially aliasing the previous store
MOV rdx, [r14 + rdx] # dependent load
MFENCE
