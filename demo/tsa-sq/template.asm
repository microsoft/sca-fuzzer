.intel_syntax noprefix

# ----------------------------- Kernel-mode Actor (Victim) -------------------
.section .data.main
.function_main_0:
    # observer start
    .macro.set_k2u_target.user.function_user_0:
    .macro.set_u2k_target.main.function_main_1:
    .macro.switch_k2u.user.0:


.function_main_1:
    .macro.landing_u2k.main_1:

    # secret injection
    .macro.random_instructions.64.32.main_1:

    .macro.set_k2u_target.user.function_user_1:
    .macro.set_u2k_target.main.function_main_2:
    .macro.switch_k2u.user.1:

.function_main_2:
    .macro.landing_u2k.main_2:

.macro.fault_handler:
    .macro.set_k2u_target.user.function_user_2:
    .macro.set_u2k_target.main.function_main_3:
    .macro.switch_k2u.user.2:

.function_main_3:
    .macro.landing_u2k.main_3:
    nop

# ----------------------------- User-mode Actor ------------------------------
.section .data.user
.function_user_0:
    .macro.landing_k2u.user_0:
    .macro.measurement_start:
    .macro.switch_u2k.main.user_0:
    lfence


.function_user_1:
    .macro.landing_k2u.user_1:
    xor rax, rax  # noremove
    mov rax, qword ptr [r14 + 0x2000] # noremove
    mov rbx, qword ptr [r14 + 0x2008] # noremove
    mov rcx, qword ptr [r14 + 0x2010] # noremove
    mov rdx, qword ptr [r14 + 0x2018] # noremove
    mov rsi, qword ptr [r14 + 0x2020] # noremove
    mov rdi, qword ptr [r14 + 0x2028] # noremove
    lfence

    # secret retrieval
    .macro.random_instructions.64.32.user_1:

    # make sure the model doesn't attempt to go further than this point
    lfence  # noremove

    .macro.measurement_end.user_1:
    .macro.switch_u2k.main.1:
    lfence


.function_user_2:
    .macro.landing_k2u.user_2:
    .macro.measurement_end.user_2:
    .macro.switch_u2k.main.2:
    lfence


# ----------------------------- Exit -----------------------------------------
.section .data.main
.test_case_exit:
