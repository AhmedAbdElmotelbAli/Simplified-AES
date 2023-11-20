#ifndef AES_H_INCLUDED
#define AES_H_INCLUDED

#include "TYPES.h"

/* Add the round key to the given block */
void add_rnd_key(i16_t* block, i16_t* rnd_key);
/* Substitute the given array of four nibbles with another four nibbles
 * (for encryption)
 */
void sub_nibbles(i16_t *block);

/* Substitute the given array of four nibbles with another four nibbles
 * (for decryption)
 */
void inv_sub_nibbles(i16_t *block);
/* Shift rows operation for encryption */
void shft_rows(i16_t* block);

/* Mix the columns of the given 4 nibbles, used for encryption */
void mix_cols(i16_t* block);

/* Mix the columns of the given 4 nibbles, used for decryption */
void inv_mix_cols(i16_t *block);
/* Expand the given 16 bit key to three subkeys nibble array */
void key_exp(i16_t key, i32_t* subkey[0][3]);

/* Addition in GF(2^4) */
i8_t gf_add(i8_t c, i8_t d);

/* Multiplication in GF(2^4) */
i8_t gf_mul(i8_t a, i8_t b);
/* Encrypt the given plaintext message to the ciphertext */
void saes_encrypt(i4_t* plaintext, i4_t *ciphertext, i64_t size, i16_t key);

/* Decrypt the given ciphertext message to the plaintext */
void saes_decrypt(i8_t *ciphertext, i8_t *plaintext, i64_t size, i16_t key);


/* Inverse shift rows operation decryption */
#define inv_shft_rows shft_rows
/* Galois Field Degree */
#define GF_DEGREE        (0x04)
/* Reducing polynomial for GF(2^4) */
#define GF_REDUCING_POLY (0x13)

#endif // AES_H_INCLUDED
