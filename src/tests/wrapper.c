#include <stdlib.h>
extern void test_case_main();

int main(int argc, const char *argv[]) {
    char *p = malloc(4096 * 1024);
    p += 512 * 4096;
    asm("mov %0, %%r14": "=r" (p)::);
    test_case_main();
    return 0;
}