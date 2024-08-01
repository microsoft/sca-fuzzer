.intel_syntax noprefix
.test_case_enter:

# ----------------------------- actor 1 ------------------------------------------------------------
.section .data.main
.function_main1:

.function_main2:
    .macro.set_h2g_target.actor2.function_a2:
    .macro.set_g2h_target.main.function_fin:
    .macro.switch_h2g.actor2:

.function_fin:
    .macro.landing_g2h:
    nop

# ----------------------------- actor 2 ------------------------------------------------------------
.section .data.actor2
.function_a2:
    .macro.landing_h2g:
    .macro.measurement_start:
    .macro.measurement_end:

    .macro.switch_g2h.main:

# ----------------------------- exit    ------------------------------------------------------------
.test_case_exit:
