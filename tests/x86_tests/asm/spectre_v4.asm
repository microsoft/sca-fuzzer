.intel_syntax noprefix
.section .data.main

# the leaked value - rcx
# construct a page offset in the range [0x200; 0x900]
and rcx, 0b11100000000
add rcx, 0x200

# save the offset into [r14 + 0]
mov qword ptr [r14], rcx
mfence

# create a delay on rbx
mov rax, 0
and rbx, 0b111000
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]
lea rbx, qword ptr [rbx + rax + 1]
lea rbx, qword ptr [rbx + rax - 1]

# sequence of potentially aliasing store-load
# if rbx == 0, they alias and rdx = 0x40
# if rbx != 0, they do not alias and rdx = offset saved above
mov qword ptr [r14 + rbx], 0x40  # store offset 0x40
mov rdx, qword ptr [r14]  # load the offset; misprediction happens here

# dependent load with the offset
and rdx, 0b111111000000
mov rdx, qword ptr [r14 + rdx]
mfence

.test_case_exit:
