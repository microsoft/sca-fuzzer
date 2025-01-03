.intel_syntax noprefix
.section .data.main

.function_0:
.bb_0:

  # line with a comment
nop # no operands
div rbx  # one operand
and rax, rax # two operands
and rax, 0b0111111000000 # immediate value - binary
and rax, 42 # immediate value - decimal
and rax, 0xfa # immediate value - hex
and rax, -1 # immediate value - negative
and rdi, r14  # reserved register
neg rax  # lowercase
mov rax, qword ptr [r14]  # load - simple addressing
mov rax, qword ptr [r14 + rbx]  # load - two parts
mov rax, qword ptr [r14 + rbx + 8]  # load - three parts
mov rax, qword ptr [r14 + rbx]  # store
lock adc dword ptr [r14 + rbx], eax  # lock prefix
and rax, rax # instrumentation

mov rdi, rdi # multiple matches


jmp .bb_1
  .bb_1:
      and rdi, 0b0111111000000 # indentation
     cmp qword ptr [ r14 + rdi ] , 59   # extra spaces
    and rdi, 0b0111111000000 # instrumentation
    cmpxchg byte ptr [r14 + rsi], sil

.test_case_exit:
