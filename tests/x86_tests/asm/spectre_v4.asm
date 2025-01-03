.intel_syntax noprefix
.section .data.main

# the leaked value - rcx
# construct a page offset in the range [0x200; 0x900]
and rcx, 0b11100000000
add rcx, 0x200

# save the offset into the offset 0
mov qword ptr [r14], rcx
mfence

# create a delay on rbx
mov rax, 0
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


# store and load, potentially matching
and rbx, 0b111000000
mov qword ptr [r14 + rbx], 0x100  # store offset 0x100
mov rdx, qword ptr [r14]  # load the offset; misprediction happens here

# dependent load with the offset
and rdx, 0b111111000000
mov rdx, qword ptr [r14 + rdx]
mfence

.test_case_exit:
