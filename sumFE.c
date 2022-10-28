#include "contiki.h"
#include "c25519.h"
#include "ed25519.h"
#include "f25519.h"
#include "ecc.h"

#include <stdio.h>             
#include <assert.h> 
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>


//Definition of a ciphertext
typedef struct {
    struct ed25519_pt *C1;
    struct ed25519_pt *C2;
} Ciphertext;

void show_point(const char *label, struct ed25519_pt *in)
{
    uint8_t x[F25519_SIZE], y[F25519_SIZE];
    ed25519_unproject(x, y, in);
    
    int i;
    printf("%s = ", label);
    printf("(");
    for (i = 0; i < F25519_SIZE; i++)
        printf("%02x", x[i]);
    printf(", ");
    for (i = 0; i < F25519_SIZE; i++)
        printf("%02x", y[i]);
    printf(")\n");
}

void show_str(const char *label, const uint8_t *s, size_t len)
{
        unsigned int i;

        printf("%s = ", label);
        for (i = 0; i < (unsigned int) len; ++i) {
                printf("%02x", s[i]);
        }
        printf("\n");
}

//Function to generate a secret value
int genKey(uint8_t *key){
    for (int i = 0; i < ED25519_EXPONENT_SIZE; i++){
        key[i] = rand();
    }
    c25519_prepare(key);

    return 1;

}

//Function to compute scalar multiplication
int computePoint(uint8_t *inB, struct ed25519_pt *inP, struct ed25519_pt *outP) {
    ed25519_smult(outP, inP, inB);
    return 1;
}

//Function to encrypt a message
int _Encrypt(struct ed25519_pt *msg, struct ed25519_pt *pk, struct ed25519_pt *C, uint8_t *r) {
    struct ed25519_pt rY;
    struct ed25519_pt res;

    //compute rY
    ed25519_smult(&rY, pk, r);
    //show_point("rY", &rY);

    //compute M + rY
    ed25519_add(&res, msg, &rY);
    show_point("Q (M + rY)", &res);

    //copy contents of res into the second component of the Ciphertext struct
    ed25519_copy(C, &res);

    return 1;
}

//Function to decrypt the ciphertext
int _Decrypt(uint8_t *sk, struct ed25519_pt *rG, struct ed25519_pt *C){
    uint8_t negS[F25519_SIZE], rY_x[F25519_SIZE], rY_y[F25519_SIZE];
    struct ed25519_pt rY;
    struct ed25519_pt _rY;
    struct ed25519_pt res;

    //============== Compute -sP where P = rG
    //compute rY = sP
    ed25519_smult(&rY, rG, sk);
    //show_point("rY", &rY);

    ed25519_unproject(rY_x, rY_y, &rY);
    
    // compute _rY = -sP
    f25519_neg(negS, rY_x);
    ed25519_project(&_rY, negS, rY_y);

    //Compute res = -sP + Q
    ed25519_add(&res, C, &_rY);
    show_point("Decrypted M", &res);
    
    return 1;
}

//Function to add 2 points on the Twisted Edwards Curve
int _addPoints(struct ed25519_pt *in1, struct ed25519_pt *in2, struct ed25519_pt *out){
    struct ed25519_pt res;

    ed25519_add(&res, in1, in2);
    ed25519_copy(out, &res);

    return 1;
}

int _addBigInt(uint8_t *key1, uint8_t *key2, uint8_t *outkey){
    unsigned int k1[NUM_ECC_WORDS];
    unsigned int k2[NUM_ECC_WORDS];
    unsigned int out[NUM_ECC_WORDS];

    //Convert uint8_t to uECC_word for the private key
    uECC_vli_bytesToNative(k1, key1, BITS_TO_BYTES(256));
    uECC_vli_bytesToNative(k2, key2, BITS_TO_BYTES(256));

    uECC_vli_add(out, k1, k2, NUM_ECC_WORDS);

    //Convert uECC word to uint8_t
    uECC_vli_nativeToBytes(outkey, BITS_TO_BYTES(256), out);

    return 1;

} 

PROCESS(sum_FE, "Functional Encryption Process");
AUTOSTART_PROCESSES(&sum_FE);

PROCESS_THREAD(sum_FE, ev, data){
    PROCESS_BEGIN();

    srand(85699);
    printf("========= WELCOME TO THE SUMFE APPLICATION =============\n");
    printf("Lets Begin\n");

    uint8_t skA[F25519_SIZE], skB[F25519_SIZE], fdk[F25519_SIZE];
    struct ed25519_pt pkA;
    struct ed25519_pt pkB;
    struct ed25519_pt pkT;
    struct ed25519_pt G;

    //Store the value of G
    ed25519_copy(&G, &ed25519_base);

    //Generate secret keys and public keys
    genKey(skA);
    show_str("\nskA", skA, F25519_SIZE);
    genKey(skB);
    show_str("skB", skB, F25519_SIZE);

    computePoint(skA, &G, &pkA);
    show_point("pkA", &pkA);
    computePoint(skB, &G, &pkB);
    show_point("pkB", &pkB);

    //Generate Functional Decryption Key
    _addBigInt(skA, skB, fdk);
    show_str("\nFDK", fdk, F25519_SIZE);

    //Compute the Master Encryption Key
    _addPoints(&pkA, &pkB, &pkT);
    show_point("pkT", &pkT);

    //Test Loading Small constants
    printf("\n========== Plaintext Inputs =============\n");
    uint8_t unloaded_a = 15;
    uint8_t unloaded_b = 25;

    uint8_t loaded_a[F25519_SIZE];
    uint8_t loaded_b[F25519_SIZE];

    f25519_load(loaded_a, unloaded_a);
    f25519_load(loaded_b, unloaded_b);

    show_str("x_1", loaded_a, F25519_SIZE);
    show_str("x_2", loaded_b, F25519_SIZE);

    struct ed25519_pt map1;
    struct ed25519_pt map2;
    struct ed25519_pt mapT;

    computePoint(loaded_a, &G, &map1);
    computePoint(loaded_b, &G, &map2);
    show_point("X_1", &map1);
    show_point("X_2", &map2);

    uint8_t _sum[F25519_SIZE];
    _addBigInt(loaded_a, loaded_b, _sum);
    show_str("x_1 + x_2", _sum, F25519_SIZE);
    computePoint(_sum, &G, &mapT);
    show_point("X_1 + X_2", &mapT);
   
    // //==================================================
    // //El-Gamal Encryption Process
    uint8_t r[F25519_SIZE];
    struct ed25519_pt rG;
    struct ed25519_pt c1;
    struct ed25519_pt c2;
    struct ed25519_pt cS;

    printf("\n========== El-Gamal Encryption Process =============\n");
    //compute r and rG
    genKey(r);
    show_str("r", r, F25519_SIZE);

    computePoint(r, &G, &rG);
    show_point("P (rG)", &rG);

    printf("Encryption 1\n");
    _Encrypt(&map1, &pkA, &c1, r);
    printf("Encryption 2\n");
    _Encrypt(&map2, &pkB, &c2, r);
    printf("Encryption of Sum\n");
    // printf("Test Sum Cipher Encryption\n");
    _Encrypt(&mapT, &pkT, &cS, r);


    //==================================================
    //El-Gamal Decryption Process
    printf("\n========== El-Gamal Decryption Process =============\n");
    printf("Decryption 1\n");
    _Decrypt(skA, &rG, &c1);
    printf("Decryption 2\n");
    _Decrypt(skB, &rG, &c2);
    // printf("Decryption of plaintext sum\n");
    // _Decrypt(fdk, &rG, &cS);


    printf("\n========== FE Ciphertext Addition and Decryption Process =============\n");
    struct ed25519_pt cT;
    _addPoints(&c1, &c2, &cT);
    show_point("C1 + C2", &cT);
    _Decrypt(fdk, &rG, &cT);
    
    PROCESS_END();
}
