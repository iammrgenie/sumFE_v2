#ifndef __TEST_ECC_UTILS_H__
#define __TEST_ECC_UTILS_H__

//#include <ecc_dh.h>
#include "ecc.h"
#include "test_uti.h"

#include <stdbool.h>

int hex2int (char hex);


/*
 * Convert hex string to byte string
 * Return number of bytes written to buf, or 0 on error
 */
int hex2bin(uint8_t *buf, const size_t buflen, const char *hex,
	    const size_t hexlen);

/*
 * Convert hex string to zero-padded nanoECC scalar
 */
void string2scalar(unsigned int * scalar, unsigned int num_word32, char *str);


void print_ecc_scalar(const char *label, const unsigned int * p_vli,
		      unsigned int num_word32);

int check_ecc_result(const int num, const char *name,
		      const unsigned int *expected, 
		      const unsigned int *computed,
		      const unsigned int num_word32, const bool verbose);

/* Test ecc_make_keys, and also as keygen part of other tests */
int keygen_vectors(char **d_vec, char **qx_vec, char **qy_vec, int tests, bool verbose);

void vli_print_bytes(uint8_t *vli, unsigned int size);


int check_code(const int num, const char *name, const int expected,
		const int computed, const int verbose);


#endif /* __TEST_ECC_UTILS_H__ */

