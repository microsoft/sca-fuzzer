.section .data.main

.function_0:
.bb_0:

isb  // instrumentation

  // line with a comment

adc w11, w20, w10  // register operands
and x13, x13, #0b1111111000000     // immediate operand
add x13, x13, x30 // instrumentation
ldrh w23, [x13], #-115 // memory operand

b.ne .bb_main.1
  .bb_main.1:
    adc w1, w2, w3  // indentation
    and x30, x30, #0b1111111000000
    add x30, x30, x30
        ldrh w28, [ x30],     #-143    // extra spaces


.test_case_exit:
