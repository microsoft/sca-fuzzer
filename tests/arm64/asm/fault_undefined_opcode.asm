.section .data.main

// instrumentation to prevent page faults
and x0, x0, #0b1111111111111

// undefined instruction to trigger Undefined Instruction exception
udf #0

// this instruction should not be executed architecturally but may be executed transiently
ldr x1, [x20, x0]

.test_case_exit:
