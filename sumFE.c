#include "contiki.h"
#include "c25519.h"
#include "ed25519.h"
#include "f25519.h"
#include "ecc.h"
#include "energest.h"


#include <stdio.h>             
#include <assert.h> 
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define CNT 25


//Definition of a ciphertext
typedef struct {
    uint8_t skey[F25519_SIZE];
    uint8_t plain[F25519_SIZE];
    struct ed25519_pt pkey;
    struct ed25519_pt x_map;
    struct ed25519_pt C;
} Experim;

static unsigned long to_seconds(uint64_t time)
{
  return (unsigned long)(time / ENERGEST_SECOND);
}

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
    for (int i = 0; i < F25519_SIZE; i++){
        key[i] = rand() % 20;
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

    Experim Test1[CNT];                     //Initate number of users for the experiments

    srand(882099);
    printf("========= WELCOME TO THE SUMFE APPLICATION =============\n");
    printf("Lets Begin\n");

    struct ed25519_pt G;

    //Store the value of G
    ed25519_copy(&G, &ed25519_base);

    //==================================================
    //Key Generation Process
    printf("\n========== Key Generation =============\n");
    clock_time_t st1 = clock_time();
    
    for (int i = 0; i < CNT; i++){
        genKey(Test1[i].skey);
        printf("\nUser %d's ", i);
        show_str("Secret Key ", Test1[i].skey, F25519_SIZE);

        computePoint(Test1[i].skey, &G, &Test1[i].pkey);
        show_point("Public Key", &Test1[i].pkey);
    }

    clock_time_t et1 = clock_time();
    unsigned long tt1 = et1 - st1;
    printf("\nTime Taken to Generate %d Key Pair(s) -- (Setup): %lu ticks\n", CNT, tt1);

    //Generate random plaintext values
    printf("\n========== Plaintext Inputs =============\n");
    uint8_t _sum[F25519_SIZE];
    struct ed25519_pt plainT;

    for (int j = 0; j < CNT; j++){
        uint8_t unloaded_x = rand() & 75;
        f25519_load(Test1[j].plain, unloaded_x);

        printf("User %d's ", j);
        show_str("x_1", Test1[j].plain, F25519_SIZE);

    }

    f25519_copy(_sum, Test1[0].plain);
     for (int i = 1; i < CNT; i ++){
        _addBigInt(Test1[i].plain, _sum, _sum);
    }

    show_str("Sum of Plaintexts", _sum, F25519_SIZE);
    computePoint(_sum, &G, &plainT);
    show_point("Mapping of Sum", &plainT);

    //==================================================
    //Encryption Process
    uint8_t r[F25519_SIZE];
    struct ed25519_pt rG;

    printf("\n========== Encryption Process =============\n");
    //compute r and rG
    clock_time_t st2 = clock_time();
    genKey(r);
    show_str("r", r, F25519_SIZE);

    computePoint(r, &G, &rG);
    show_point("P (rG)", &rG);

    for (int i = 0; i < CNT; i++){
        // Perform the Mapping
        computePoint(Test1[i].plain, &G, &Test1[i].x_map);
        show_point("X_i (Mapped)", &Test1[i].x_map);

        //Encrypt
        _Encrypt(&Test1[i].x_map, &Test1[i].pkey, &Test1[i].C, r);
        printf("\n");
    }

    clock_time_t et2 = clock_time();
    unsigned long tt2 = et2 - st2;
    printf("\nTime Taken to Encrypt %d plaintext(s) -- (Encryption): %lu ticks\n", CNT, tt2);


    //==================================================
    // Decryption Process
    printf("\n========== Basic Decryption Process =============\n");
    
    clock_time_t st3 = clock_time();

    for (int i = 0; i < CNT; i++){
        _Decrypt(Test1[i].skey, &rG, &Test1[i].C);
    }

    clock_time_t et3 = clock_time();
    unsigned long tt3 = et3 - st3;
    printf("\nTime Taken to Decrypt %d ciphertext(s) -- (Not Important): %lu ticks\n", CNT, tt3);
    
    //FE Key Generation Process
    printf("\n========== FE Key Generation Process =============\n");
    clock_time_t stK = clock_time();
    uint8_t fdk[F25519_SIZE];
    f25519_copy(fdk, Test1[0].skey);

    for (int i = 1; i < CNT; i ++){
        _addBigInt(Test1[i].skey, fdk, fdk);
    }

    clock_time_t etK = clock_time();
    show_str("FDK", fdk, F25519_SIZE);

    unsigned long ttK = etK - stK;
    printf("\nTime Taken to generate a Decryption Key -- (KeyGen) for %d user(s): %lu ticks\n", CNT, ttK);



    //==================================================
    //FE Decryption Process
    printf("\n========== FE Ciphertext Decryption Process =============\n");    
    struct ed25519_pt cT;

    clock_time_t st4 = clock_time();
    
    ed25519_copy(&cT, &Test1[0].C);

    // show_str("x_1 + x_2", _sum, F25519_SIZE);
    // show_str("FDK", fdk, F25519_SIZE);

    for (int i = 1; i < CNT; i ++){
        //_addBigInt(Test1[i].skey, fdk, fdk);
        _addPoints(&Test1[i].C, &cT, &cT);
    }

    show_point("Ciphertexts Sum", &cT);
    _Decrypt(fdk, &rG, &cT);
    clock_time_t et4 = clock_time();

    unsigned long tt4 = et4 - st4;
    printf("\nTime Taken to execute FE Decryption -- (Decryption) for %d ciphertext(s): %lu ticks\n", CNT, tt4);

    energest_flush();

    printf("\nEnergest Measurements:\n");
    printf(" CPU          %4lus LPM      %4lus DEEP LPM %4lus  Total time %lus\n",
           to_seconds(energest_type_time(ENERGEST_TYPE_CPU)),
           to_seconds(energest_type_time(ENERGEST_TYPE_LPM)),
           to_seconds(energest_type_time(ENERGEST_TYPE_DEEP_LPM)),
           to_seconds(ENERGEST_GET_TOTAL_TIME()));
    printf(" Radio LISTEN %4lus TRANSMIT %4lus OFF      %4lus\n",
           to_seconds(energest_type_time(ENERGEST_TYPE_LISTEN)),
           to_seconds(energest_type_time(ENERGEST_TYPE_TRANSMIT)),
           to_seconds(ENERGEST_GET_TOTAL_TIME()
                      - energest_type_time(ENERGEST_TYPE_TRANSMIT)
                      - energest_type_time(ENERGEST_TYPE_LISTEN)));

    PROCESS_END();
}
