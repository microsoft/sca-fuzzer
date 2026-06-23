.intel_syntax noprefix

# ----------------------------- Hypervisor (Host) ----------------------------
.section .data.main
.function_main_0:
    # observer start
    .macro.set_h2g_target.vm.function_vm_0:
    .macro.set_g2h_target.main.function_main_1:
    .macro.switch_h2g.vm.0:


.function_main_1:
    .macro.landing_g2h.main_1:

    .macro.set_h2g_target.vmvictim.function_vmvictim_0:
    .macro.set_g2h_target.main.function_main_2:
    .macro.switch_h2g.vmvictim.0:

.function_main_2:
    .macro.landing_g2h.main_2:
    .macro.set_h2g_target.vm.function_vm_1:
    .macro.set_g2h_target.main.function_main_3:

    xor rax, rax  # noremove
    xor rbx, rbx  # noremove
    xor rcx, rcx  # noremove
    xor rdx, rdx  # noremove
    xor rsi, rsi  # noremove
    xor rdi, rdi  # noremove
    # insert flushing patches here
.patch_placeholder:

    .macro.switch_h2g.vm.1:

.function_main_3:
    .macro.landing_g2h.main_3:

.macro.fault_handler:
.patch_placeholder_fault_handler:

    .macro.set_h2g_target.vm.function_vm_2:
    .macro.set_g2h_target.main.function_main_4:
    .macro.switch_h2g.vm.2:

.function_main_4:
    .macro.landing_g2h.main_4:
    nop

# ----------------------------- VM - Victim ----------------------------------
.section .data.vmvictim
.function_vmvictim_0:
    .macro.landing_h2g.vmvictim_0:

    # secret injection
    .macro.random_instructions.64.32.main_1:

    .macro.switch_g2h.main.vmvictim_0:
    lfence


# ----------------------------- VM - Observer --------------------------------
.section .data.vm
.function_vm_0:
    .macro.landing_h2g.vm_0:
    .macro.measurement_start:
    .macro.switch_g2h.main.vm_0:
    lfence


.function_vm_1:
    .macro.landing_h2g.vm_1:
    xor rax, rax  # noremove
    mov rax, qword ptr [r14 + 0x2000] # noremove
    mov rbx, qword ptr [r14 + 0x2008] # noremove
    mov rcx, qword ptr [r14 + 0x2010] # noremove
    mov rdx, qword ptr [r14 + 0x2018] # noremove
    mov rsi, qword ptr [r14 + 0x2020] # noremove
    mov rdi, qword ptr [r14 + 0x2028] # noremove
    mfence # noremove

    # secret retrieval
    .macro.random_instructions.64.32.vm_1:

    # make sure the model doesn't attempt to go further than this point
    lfence  # noremove

    .macro.measurement_end.vm_1:
    .macro.switch_g2h.main.1:
    lfence


.function_vm_2:
    .macro.landing_h2g.vm_2:
    .macro.measurement_end.vm_2:
    .macro.switch_g2h.main.2:
    lfence


# ----------------------------- Exit -----------------------------------------
.section .data.main
.test_case_exit:
