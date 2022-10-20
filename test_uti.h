#ifndef __TEST_UTI_H__
#define __TEST_UTI_H__

//#include <myencrypt.h>


#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define PRINT_DATA(fmt, ...) printf(fmt, ##__VA_ARGS__)

#define PRINT_LINE                                                     \
	PRINT_DATA(                                                        \
		"============================================================" \
		"=======\n")


#define FAIL "FAIL"
#define PASS "PASS"
#define FMT_ERROR "%s - %s@%d. "

/* TC_ here stands for 'Test Case' not 'TinyCrypt' */
#define TC_PASS 0
#define TC_FAIL 1

#define TC_ERROR(fmt, ...)                               \
	do {                                                 \
		PRINT_DATA(FMT_ERROR, FAIL, __func__, __LINE__); \
		PRINT_DATA(fmt, ##__VA_ARGS__);                  \
	} while (0)

#define TC_PRINT(fmt, ...) PRINT_DATA(fmt, ##__VA_ARGS__)
#define TC_START(name) PRINT_DATA("tc_start() - %s\n", name)
#define TC_END(result, fmt, ...) PRINT_DATA(fmt, ##__VA_ARGS__)

/* prints result and the function name */
#define TC_END_RESULT(result)                           \
	do {                                                \
		PRINT_LINE;                                     \
		TC_END(result, "%s - %s.\n",                    \
			result == TC_PASS ? PASS : FAIL, __func__); \
	} while (0)

#define TC_END_REPORT(result)                               \
	do {                                                    \
		PRINT_LINE;                                         \
		TC_END(result,                                      \
			"PROJECT EXECUTION %s\n",               \
			result == TC_PASS ? "SUCCESSFUL" : "FAILED");   \
	} while (0)


// int default_CSPRNG(uint8_t *dest, unsigned int size) 
// {

//   /* input sanity check: */
//   if (dest == (uint8_t *) 0 || (size <= 0))
//     return 0;

//   int i;

//   for (i = 0; i < size; ++i)
//   {
//     dest[i] = rand();
//   }

//   return 1;
// }

static inline void show_str(const char *label, const uint8_t *s, size_t len)
{
        unsigned int i;

        TC_PRINT("%s = ", label);
        for (i = 0; i < (unsigned int) len; ++i) {
                TC_PRINT("%02x", s[i]);
        }
        TC_PRINT("\n");
}

static inline void fatal(unsigned int testnum, const void *expected, size_t expectedlen,
           const void *computed, size_t computedlen)
{

        TC_ERROR("\tTest #%d Failed!\n", testnum);
        show_str("\t\tExpected", expected, expectedlen);
        show_str("\t\tComputed  ", computed, computedlen);
        TC_PRINT("\n");
}

static inline unsigned int check_result(unsigned int testnum, const void *expected, size_t expectedlen,
                   const void *computed, size_t computedlen)
{
	unsigned int result = TC_PASS;

        if (expectedlen != computedlen) {
                TC_ERROR("The length of the computed buffer (%zu)", computedlen);
                TC_ERROR("does not match the expected length (%zu).", expectedlen);
                result = TC_FAIL;
        } else if (memcmp(computed, expected, computedlen) != 0) {
                fatal(testnum, expected, expectedlen, computed, computedlen);
                result = TC_FAIL;
        }

        return result;
}

#endif /* __TEST_UTILS_H__ */
