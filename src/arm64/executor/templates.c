/// File: Measurement templates for various threat models
///
// Copyright (C) Microsoft Corporation
// SPDX-License-Identifier: MIT

// -----------------------------------------------------------------------------------------------

#include "main.h"
#include <linux/string.h>

#define TEMPLATE_ENTER 0x00001111
#define TEMPLATE_INSERT_TC 0x00002222
#define TEMPLATE_RETURN 0x00003333

#define xstr(s) _str(s)
#define _str(s) str(s)
#define str(s) #s

int load_template(size_t tc_size) {
    unsigned template_pos = 0;
    unsigned code_pos = 0;

    // skip until the beginning of the template
    for (;; template_pos++) {
        if (template_pos >= MAX_MEASUREMENT_CODE_SIZE)
            return -1;

        if (*(uint32_t *) &measurement_template[template_pos] == TEMPLATE_ENTER) {
            template_pos += 4;
            break;
        }
    }

    // copy the first part of the template
    for (;; template_pos++, code_pos++) {
        if (template_pos >= MAX_MEASUREMENT_CODE_SIZE)
            return -1;

        if (*(uint32_t *) &measurement_template[template_pos] == TEMPLATE_INSERT_TC) {
            template_pos += 4;
            break;
        }

        measurement_code[code_pos] = measurement_template[template_pos];
    }

    // copy the test case into the template
    memcpy(&measurement_code[code_pos], test_case, tc_size);
    code_pos += tc_size;

    // write the rest of the template
    for (;; template_pos++, code_pos++) {
        if (template_pos >= MAX_MEASUREMENT_CODE_SIZE)
            return -2;

        if (*(uint32_t *) &measurement_template[template_pos] == TEMPLATE_INSERT_TC)
            return -3;

        if (*(uint32_t *) &measurement_template[template_pos] == TEMPLATE_RETURN)
            break;

        measurement_code[code_pos] = measurement_template[template_pos];
    }

    // RET
    measurement_code[code_pos + 0] = '\xc0';
    measurement_code[code_pos + 1] = '\x03'; 
    measurement_code[code_pos + 2] = '\x5f'; 
    measurement_code[code_pos + 3] = '\xd6'; 
    return code_pos + 4;
}

// =================================================================================================
// Template building blocks
// =================================================================================================
inline void prologue(void) {
}

inline void epilogue(void) {
}

// =================================================================================================
// L1D Prime+Probe
// =================================================================================================

void template_l1d_prime_probe(void) {
    asm volatile(".long "xstr(TEMPLATE_ENTER));

    // ensure that we don't crash because of BTI
    asm volatile("bti c");

    prologue();
    // Execute the test case
    asm("\nisb\n"
        ".long "xstr(TEMPLATE_INSERT_TC)" \n"
        "isb\n");

    epilogue();
    asm volatile(".long "xstr(TEMPLATE_RETURN));
}
