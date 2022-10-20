#include "contiki.h"
#include "ecc.h"
#include "test_ecc_utils.h"
#include "test_uti.h"

#include <stdio.h>              //For printf
#include <assert.h> 
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define default_RNG_defined 1

//Definition of a ciphertext
typedef struct {
    uint8_t c1[2 * NUM_ECC_BYTES];
    uint8_t c2[2 * NUM_ECC_BYTES];
} Ciphertext;


int default_CSPRNG(uint8_t *dest, unsigned int size) 
{

  /* input sanity check: */
  if (dest == (uint8_t *) 0 || (size <= 0))
    return 0;

  int i;

  for (i = 0; i < size; ++i)
  {
    dest[i] = rand();
  }

  return 1;
}

int conUint2uECC(uint8_t *in, uECC_Curve curve, uECC_word_t *out){
    uECC_vli_bytesToNative(out, in, curve->num_bytes);
    uECC_vli_bytesToNative(out + curve->num_words, in + curve->num_bytes, curve->num_bytes);
    return 1;
}

int conuECC2Uint(uECC_word_t *in, uECC_Curve curve, uint8_t *out) {
    uECC_vli_nativeToBytes(out, curve->num_bytes, in);
    uECC_vli_nativeToBytes(out + curve->num_bytes, curve->num_bytes, in + curve->num_words);
    return 1;
}

int _addPoints(uint8_t *in1, uint8_t *in2, uint8_t *_out, uECC_Curve curve) {
    uECC_word_t t1[NUM_ECC_WORDS * 2];
    uECC_word_t t2[NUM_ECC_WORDS * 2];
    uECC_word_t _sum[NUM_ECC_WORDS * 2];

    conUint2uECC(in1, curve, t1);
    conUint2uECC(in2, curve, t2);

	uECC_word_t carry = 0;
	wordcount_t i;
	for (i = 0; i < (NUM_ECC_WORDS * 2); ++i) {
		uECC_word_t sum = t1[i] + t2[i] + carry;
		uECC_word_t val = (sum < t1[i]);
		carry = cond_set(val, carry, (sum != t1[i]));
		_sum[i] = sum;
	}

    //void uECC_vli_set(uECC_word_t *dest, const uECC_word_t *src, wordcount_t num_words);

    conuECC2Uint(_sum, curve, _out);

    return 1;
}

int gen_random_secret(uint8_t *sk, uECC_Curve curve){
    uECC_word_t _random[NUM_ECC_WORDS * 2];
    uECC_word_t priv[NUM_ECC_WORDS];

    uECC_word_t try;

    for (try = 0; try < uECC_RNG_MAX_TRIES; ++try){
        uECC_RNG_Function rng_function = uECC_get_rng();

        if (!rng_function || !rng_function((uint8_t*)_random, 2 * NUM_ECC_WORDS * uECC_WORD_SIZE)){
            return 0;
        } 

        //Reduce _random to fit priv
        uECC_vli_mmod(priv, _random, curve->n, BITS_TO_WORDS(curve->num_n_bits));

        //Convert uECC word to uint8_t
        uECC_vli_nativeToBytes(sk, BITS_TO_BYTES(curve->num_n_bits), priv);

        //Erase temporary buffer used to store the private key
        memset(priv, 0, NUM_ECC_BYTES);
    }

    return 0;
}

int genPK(uint8_t *sk, uint8_t *out, const uECC_word_t *P, uECC_Curve curve){
    uECC_word_t _public[NUM_ECC_WORDS * 2];
    uECC_word_t _priv[NUM_ECC_WORDS];

    uECC_word_t tmp1[NUM_ECC_WORDS];
 	uECC_word_t tmp2[NUM_ECC_WORDS];
	uECC_word_t *p2[2] = {tmp1, tmp2};
	uECC_word_t carry;

    //Convert uint8_t to uECC_word for the private key
    uECC_vli_bytesToNative(_priv, sk, BITS_TO_BYTES(curve->num_n_bits));

    //Regularize the bitcount as a measure against side-channel analysis
    carry = regularize_k(_priv, tmp1, tmp2, curve);

    //ECC point multiplication against G
    EccPoint_mult(_public, P, p2[!carry], 0, curve->num_n_bits + 1, curve);

    if (EccPoint_isZero(_public, curve)){
        return 0;
    }

    //Convert and store the public key
    conuECC2Uint(_public, curve, out);
    // uECC_vli_nativeToBytes(out, curve->num_bytes, _public);
    // uECC_vli_nativeToBytes(out + curve->num_bytes, curve->num_bytes, _public + curve->num_words);

    memset(_priv, 0, NUM_ECC_BYTES);

    return 1;
}

int mapPlainText(unsigned int *in, uECC_Curve curve, uint8_t * out) {
    uECC_word_t tmp1[NUM_ECC_WORDS];
 	uECC_word_t tmp2[NUM_ECC_WORDS];
	uECC_word_t *p2[2] = {tmp1, tmp2};
	uECC_word_t carry;

    uECC_word_t _public[NUM_ECC_WORDS * 2];
    
    //Regularize the bitcount as a measure against side-channel analysis
    carry = regularize_k(in, tmp1, tmp2, curve);
    
    //ECC point multiplication against G
    EccPoint_mult(_public, curve->G, p2[!carry], 0, curve->num_n_bits + 1, curve);

    if (EccPoint_isZero(_public, curve)){
        printf("Not a point on the curve");
        return 0;
    }

    //Convert and store the public key
    conuECC2Uint(_public, curve, out);
    // uECC_vli_nativeToBytes(out, curve->num_bytes, _public);
    // uECC_vli_nativeToBytes(out + curve->num_bytes, curve->num_bytes, _public + curve->num_words);
    
    return 1;
}


int _Encrypt(uint8_t * in_msg, uint8_t * pk, uECC_Curve curve, Ciphertext *C){
    uint8_t r[NUM_ECC_BYTES];
    uint8_t rG[2 * NUM_ECC_BYTES];
    uint8_t rY[2 * NUM_ECC_BYTES];
    uECC_word_t Y[NUM_ECC_WORDS * 2];

    //generate random variable r in [1, N-1]
    gen_random_secret(r, curve);

    //compute rG
    genPK(r, rG, curve->G, curve);

    //convert pk into Y
    conUint2uECC(pk, curve, Y);
    
    //Check conversion
    if (EccPoint_isZero(Y, curve)){
        printf("Not a point on the curve");
        return 0;
    }

    //Compute rY
    genPK(r, rY, (const uECC_word_t *)Y, curve);

    //Print Parameters
    show_str("rG: ", rG, sizeof(rG));
    show_str("rY: ", rY, sizeof(rY));

    //Compute M + rY
    uint8_t res[2 * NUM_ECC_BYTES];
    _addPoints(rY, in_msg, res, curve);
    show_str("M_i + rY: ", res, sizeof(res));

    //Store Ciphertext into struct
    for (wordcount_t x = 0; x < (2 * NUM_ECC_BYTES); x++){
        C->c1[x] = rG[x];
        C->c2[x] = res[x];
    }

    // show_str("Ciphertext C1 : ", C->c1, sizeof(C->c1));
    // show_str("Ciphertext C2 : ", C->c2, sizeof(C->c2));
    return 0;

}

int _Decrypt(uint8_t * sk, uECC_Curve curve, Ciphertext *C){
    uECC_word_t _priv[NUM_ECC_WORDS];
    uECC_word_t _inv[NUM_ECC_WORDS];

    uint8_t t1[NUM_ECC_BYTES];
    uint8_t t2[2 * NUM_ECC_BYTES];
    uint8_t res[2 * NUM_ECC_BYTES];

    uECC_word_t P[NUM_ECC_WORDS * 2];
    //uECC_word_t Q[NUM_ECC_WORDS * 2];
    
    //Convert uint8_t to uECC_word for the private key
    uECC_vli_bytesToNative(_priv, sk, BITS_TO_BYTES(curve->num_n_bits));

    //Convert ciphertext parameters to uECC
    conUint2uECC(C->c1, curve, P);
    //conUint2uECC(C->c2, curve, Q);

    //compute inverse of the secret key
    uECC_vli_modInv(_inv, _priv, curve->n, NUM_ECC_WORDS);
    uECC_vli_nativeToBytes(t1, BITS_TO_BYTES(curve->num_n_bits), _inv);
    show_str("Inverted Key : ", t1, sizeof(t1));

    //compute t2 = -sP where P = rG
    genPK(t1, t2, (const uECC_word_t *)P, curve);

    //compute res = -sP + Q 
    _addPoints(t2, C->c2, res, curve);
    show_str("Decrypted Message: ", res, sizeof(res));
    
    return 1;
}


PROCESS(sum_FE, "Functional Encryption Process");
AUTOSTART_PROCESSES(&sum_FE);

PROCESS_THREAD(sum_FE, ev, data){
    PROCESS_BEGIN();

    printf("========= WELCOME TO THE SUMFE APPLICATION =============\n");
    printf("Lets Begin\n");

    // printf("Clock Time = %ld\n", clock_time());
    srand(8574);
    uECC_set_rng(&default_CSPRNG);

    //Initialize curve for computations
    const struct uECC_Curve_t * curve = uECC_secp256r1();

    uint8_t secKey[NUM_ECC_BYTES];
    uint8_t pubKey[2 * NUM_ECC_BYTES];

    gen_random_secret(secKey, curve);

    show_str("ECC Private Key 1: ", secKey, sizeof(secKey));

    genPK(secKey, pubKey, curve->G, curve);
    show_str("ECC Public Key 1: ", pubKey, sizeof(pubKey));

    //Generate random value
    unsigned int x_i = 5;
    printf("Generated Plaintext (X_I) = %d\n", x_i);

    uint8_t mapX_I[2 * NUM_ECC_BYTES];
    mapPlainText(&x_i, curve, mapX_I);
    show_str("X_I Mapped : ", mapX_I, sizeof(mapX_I));

    Ciphertext C1;
    _Encrypt(mapX_I, pubKey, curve, &C1);
    show_str("Ciphertext C1 : ", C1.c1, sizeof(C1.c1));
    show_str("Ciphertext C2 : ", C1.c2, sizeof(C1.c2));

    //uint8_t decrypted_msg[2 * NUM_ECC_BYTES];
    _Decrypt(secKey, curve, &C1);

    PROCESS_END();
}
