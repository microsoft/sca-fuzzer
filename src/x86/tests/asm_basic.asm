.intel_syntax noprefix
LEA R14, [R14 + 40] # instrumentation
MFENCE # instrumentation
.test_case_enter:

.function_0:
.bb_0:

  # line with a comment
NOP # no operands
DIV RBX  # one operand
AND RAX, RAX # two operands
AND RAX, 0b0111111000000 # immediate value - binary
AND RAX, 42 # immediate value - decimal
AND RAX, 0xfa # immediate value - hex
AND RAX, -1 # immediate value - negative
AND RDI, R14  # reserved register
neg rax  # lowercase
MOV RAX, qword ptr [R14]  # load - simple addressing
MOV RAX, qword ptr [R14 + RBX]  # load - two parts
MOV RAX, qword ptr [R14 + RBX + 8]  # load - three parts
MOV RAX, qword ptr [R14 + RBX]  # store
LOCK ADC dword ptr [R14 + RBX], EAX  # lock prefix
AND RAX, RAX # instrumentation

MOV RDI, RDI # multiple matches


JMP .bb_1
  .bb_1:
      AND RDI, 0b0111111000000 # indentation
     CMP qword ptr [ R14 + RDI ] , 59   # extra spaces
    AND RDI, 0b0111111000000 # instrumentation
    CMPXCHG byte ptr [R14 + RSI], SIL

.exit_0:
.test_case_exit:
MFENCE # instrumentation
LEA R14, [R14 - 40] # instrumentation
