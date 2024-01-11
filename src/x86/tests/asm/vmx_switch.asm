.intel_syntax noprefix
.test_case_enter:

# ----------------------------- Actor 1 ------------------------------------------------------------
.section .data.main
.function_main1:

.function_main2:
    .macro.measurement_start:
    .macro.set_h2g_target.actor2.function_a2:
    .macro.set_g2h_target.main.function_fin:
    .macro.switch_h2g.actor2:

.function_fin:
    .macro.measurement_end:
    nop

# # ----------------------------- Actor 2 ------------------------------------------------------------
.section .data.actor2
.function_a2:
    .macro.switch_g2h.main:

# ----------------------------- Exit    ------------------------------------------------------------
.test_case_exit:
