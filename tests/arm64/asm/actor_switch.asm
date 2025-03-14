.section .data.main

.function_start:
    mov x0, #1

    .macro.switch.actor2.function_1:
# end of function_start
# --------------------------------------------------------------------------------------------------

.function_fin:
    .bb0:
    nop
# end of function_fin
# --------------------------------------------------------------------------------------------------

.section .data.actor2
.function_1:
    mov x1, #2

    .macro.switch.main.function_fin:
# end of function_1
# --------------------------------------------------------------------------------------------------

.test_case_exit:
