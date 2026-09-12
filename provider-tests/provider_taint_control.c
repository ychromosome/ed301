/* Deliberately secret-dependent TEST instrumentation control, never a DSO. */
#include <stdio.h>
#include <valgrind/memcheck.h>
#include <valgrind/valgrind.h>

int main(void)
{
    unsigned char value = 1;
    volatile unsigned char table[2] = { 17, 29 };
    volatile unsigned char result;

    if (!RUNNING_ON_VALGRIND)
        return 2;
    VALGRIND_MAKE_MEM_UNDEFINED(&value, sizeof(value));
    result = table[value];
    VALGRIND_MAKE_MEM_DEFINED(&value, sizeof(value));
    VALGRIND_MAKE_MEM_DEFINED((void *)&result, sizeof(result));
    printf("provider_taint_positive_control=%u\n", (unsigned int)result);
    return 0;
}
