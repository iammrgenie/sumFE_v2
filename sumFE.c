#include "contiki.h"
#include "ecc.h"
#include "test_ecc_utils.h"
#include "test_uti.h"

#include <stdio.h>             
#include <assert.h> 
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define default_RNG_defined 1

#define PRECOMP 10

//Definition of a ciphertext
typedef struct {
    uint8_t c1[2 * NUM_ECC_BYTES];
    uint8_t c2[2 * NUM_ECC_BYTES];
} Ciphertext;

typedef struct {
    uECC_word_t plaintext[NUM_ECC_WORDS * 2];
    uint8_t p[2 * NUM_ECC_BYTES];
} _decipher;


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

    memset(_priv, 0, NUM_ECC_BYTES);

    return 1;
}

int mapPlainText(uECC_word_t *in, uECC_Curve curve, uint8_t *out) {
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
    
    return 1;
}


int _Encrypt(uint8_t * in_msg, uint8_t * pk, uECC_Curve curve, Ciphertext *C){
    uint8_t r[NUM_ECC_BYTES];
    uint8_t rG[2 * NUM_ECC_BYTES];
    uint8_t rY[2 * NUM_ECC_BYTES];
    uECC_word_t Y[NUM_ECC_WORDS * 2];

    uECC_word_t _tmp1[NUM_ECC_WORDS * 2];
    uECC_word_t _tmp2[NUM_ECC_WORDS * 2];
    uECC_word_t _tmp3[NUM_ECC_WORDS * 2];

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
    show_str("P = (rG) ", rG, sizeof(rG));
    show_str("rY ", rY, sizeof(rY));

    //Compute M + rY
    conUint2uECC(in_msg, curve, _tmp1);
    conUint2uECC(rY, curve, _tmp2);
    uECC_vli_add(_tmp3, _tmp1, _tmp2, (NUM_ECC_WORDS * 2));

    uint8_t res[2 * NUM_ECC_BYTES];
    conuECC2Uint(_tmp3, curve, res); 
    show_str("Q = (M + rY) ", res, sizeof(res));

    //Store Ciphertext into struct
    for (wordcount_t x = 0; x < (2 * NUM_ECC_BYTES); x++){
        C->c1[x] = rG[x];
        C->c2[x] = res[x];
    }

    return 0;

}

int _Decrypt(uint8_t * sk, uECC_Curve curve, Ciphertext *C){
    uECC_word_t _tmp1[NUM_ECC_WORDS * 2];
    uECC_word_t _tmp2[NUM_ECC_WORDS * 2];

    uint8_t t1[2 * NUM_ECC_BYTES];
    uint8_t res[2 * NUM_ECC_BYTES];

    uECC_word_t P[NUM_ECC_WORDS * 2];
    uECC_word_t Q[NUM_ECC_WORDS * 2];

    //Convert ciphertext parameters to uECC
    conUint2uECC(C->c1, curve, P);
    conUint2uECC(C->c2, curve, Q);

    //compute t1 = sP where P = rG
    genPK(sk, t1, (const uECC_word_t *)P, curve);
    show_str("sP ", t1, sizeof(t1));
    show_str("Q ", C->c2, sizeof(C->c2));

    //compute res = Q - sP
    conUint2uECC(t1, curve, _tmp1);
    uECC_vli_sub(_tmp2, Q, _tmp1, (NUM_ECC_WORDS * 2));

    conuECC2Uint(_tmp2, curve, res); 
    show_str("Decrypted f_map(x) ", res, sizeof(res));
    
    return 1;
}


PROCESS(sum_FE, "Functional Encryption Process");
AUTOSTART_PROCESSES(&sum_FE);

PROCESS_THREAD(sum_FE, ev, data){
    PROCESS_BEGIN();

    printf("========= WELCOME TO THE SUMFE APPLICATION =============\n");
    printf("Lets Begin\n");

    srand(88964);
    uECC_set_rng(&default_CSPRNG);

    //Initialize curve for computations
    const struct uECC_Curve_t * curve = uECC_secp256r1();


    uint8_t secKey[NUM_ECC_BYTES];
    uint8_t pubKey[2 * NUM_ECC_BYTES];

    gen_random_secret(secKey, curve);

    show_str("ECC Private Key 1 ", secKey, sizeof(secKey));

    genPK(secKey, pubKey, curve->G, curve);
    show_str("ECC Public Key 1 ", pubKey, sizeof(pubKey));

    //Generate random value
    uECC_word_t x_i = rand() % 50;
    printf("Generated Plaintext (X_I) = %d\n", x_i);

    uint8_t mapX_I[2 * NUM_ECC_BYTES];
    mapPlainText(&x_i, curve, mapX_I);
    show_str("f_map(x) ", mapX_I, sizeof(mapX_I));

    printf("\n========= ENCRYPTION PARAMETERS =============\n");
    Ciphertext C1;
    _Encrypt(mapX_I, pubKey, curve, &C1);
    show_str("Ciphertext C1 : ", C1.c1, sizeof(C1.c1));
    show_str("Ciphertext C2 : ", C1.c2, sizeof(C1.c2));

    //uint8_t decrypted_msg[2 * NUM_ECC_BYTES];
    printf("\n========= DECRYPTION PARAMETERS =============\n");
    _Decrypt(secKey, curve, &C1);

    PROCESS_END();
}
