#include <stdint.h>
#include <stdio.h>

int main(int argc, const char *argv[]) {
    uint32_t state = 10;

    for (int j = 0; j < 10; j++) {
        for (int i = 0; i < 1001; i++) {
            asm(".intel_syntax noprefix\n"
                "IMUL %%edi, %%edi, 2891336453\n"
                "ADD %%edi, 12345\n"
                ".att_syntax noprefix": "=D" (state): "D" (state):);
            asm(".intel_syntax noprefix\n"
                "IMUL %%edi, %%edi, 2891336453\n"
                "ADD %%edi, 12345\n"
                ".att_syntax noprefix": "=D" (state): "D" (state):);
            asm(".intel_syntax noprefix\n"
                "IMUL %%edi, %%edi, 2891336453\n"
                "ADD %%edi, 12345\n"
                ".att_syntax noprefix": "=D" (state): "D" (state):);
            asm(".intel_syntax noprefix\n"
                "IMUL %%edi, %%edi, 2891336453\n"
                "ADD %%edi, 12345\n"
                ".att_syntax noprefix": "=D" (state): "D" (state):);
            asm(".intel_syntax noprefix\n"
                "IMUL %%edi, %%edi, 2891336453\n"
                "ADD %%edi, 12345\n"
                ".att_syntax noprefix": "=D" (state): "D" (state):);
            asm(".intel_syntax noprefix\n"
                "IMUL %%edi, %%edi, 2891336453\n"
                "ADD %%edi, 12345\n"
                ".att_syntax noprefix": "=D" (state): "D" (state):);
            asm(".intel_syntax noprefix\n"
                "IMUL %%edi, %%edi, 2891336453\n"
                "ADD %%edi, 12345\n"
                ".att_syntax noprefix": "=D" (state): "D" (state):);
            printf("  %u\n", state);
        }
        printf("%d %u\n", j, state);
    }

    return 0;
}
