#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include "AES.h"
#include "TYPES.h"



void add_rnd_key(i16_t* block, i16_t* rnd_key) {

    *(block) ^= *(rnd_key);

}
/**
 * @brief Substitute the given nibble using the given 4x4 S-box table
 *
 * @param nibble
 * @param _tab
 * @return i8_t
 */
static inline i4_t _sub(i4_t* nibble, i4_t _tab[4][4]) {

    /* Get the row value */
    int row = (i8_t *)((*nibble & 0b1100) >> 2);
    int col = (i8_t *)(*nibble & 0b0011);

    /* Return the substitution */
    return _tab[row][col];
}

/**
 * @brief Substitute the given array of four nibbles with another four nibbles
 *        (for encryption)
 *
 * @param block
 */
void sub_nibbles(i16_t *block) {

    static i4_t _tab[4][4] = {
        {9, 4, 10, 11},
        {13, 1, 8, 5},
        {6, 2, 0, 3},
        {12, 14, 15, 7}
    };
    i4_t x,y,z,l;
    x=(*block)>>12;
    y=(*block)>>8;
    z=(*block)>>4;
    l=(*block);
    *block = _sub(&x, _tab)<<12;

    *block |= _sub(&y, _tab)<<8;

    *block |= _sub(&z, _tab)<<4;

    *block |= _sub(&l, _tab);


}

/**
 * @brief Substitute the given array of four nibbles with another four nibbles
 *        (for decryption)
 *
 * @param block
 */
void inv_sub_nibbles(i16_t* block) {

    static i8_t _tab[4][4] = {
        {10, 5, 9, 11},
        {1, 7, 8, 15},
        {6, 0, 2, 3},
        {12, 4, 13, 14}
    };

     i4_t x,y,z,l;
    x=(*block)>>12;
    y=(*block)>>8;
    z=(*block)>>4;
    l=(*block);
    *block = _sub(&x, _tab)<<12;

    *block |= _sub(&y, _tab)<<8;

    *block |= _sub(&z, _tab)<<4;

    *block |= _sub(&l, _tab);
}
/**
 * @brief Shift the second row to the left/right by one nibble, i.e. swap the
 *        nibbles
 *
 * @param block
 */
void shft_rows(i16_t* block) {

    /* Swap the nibbles n1 and n3, which are the elements 0 and 2 of the
     * nibble array
     */
    i4_t x,y,z,l;
    x=(*block)>>12;
    y=((*block)&0x0f00)>>8;
    z=((*block)&0x00f0)>>4;
    l=(*block)&0x000f;
    *block =(x<<12)|(l<<8)|(z<<4)|y;

}


/**
 * @brief Matrix muliply two 2x2 matrices under GF(2^4) field
 *
 * @param _tab
 * @param block
 */
void _mat_mul(i8_t const_mat[4], i16_t* block) {

    /* Get the constant matrix nibbles */
    i8_t c0 = const_mat[3];
    i8_t c1 = const_mat[2];
    i8_t c2 = const_mat[1];
    i8_t c3 = const_mat[0];

    /* Get the block matrix nibbles */
      i8_t n3 = (*block)>>12;
     i8_t n2 = ((*block)&0x0f00)>>8;
    i8_t n0 = (*block)&0x000f;
    i8_t n1 = ((*block)&0x00f0)>>4;


    /* Compute each element and store the result in the block array */
    *block = gf_add(gf_mul(c0, n0), gf_mul(c2, n1));
    *block |= (gf_add(gf_mul(c1, n0), gf_mul(c3, n1)))<<4;
    *block |= (gf_add(gf_mul(c0, n2), gf_mul(c2, n3)))<<8;
    *block |= (gf_add(gf_mul(c1, n2), gf_mul(c3, n3)))<<12;
}

/**
 * @brief Mix the columns of the given 4 nibbles, used for encryption
 *        using galois field matrix multiplication
 *
 * @param block
 */
void mix_cols(i16_t *block) {

    static i8_t _tab[4] = {1, 4, 4, 1};

    _mat_mul(_tab, block);
}

/**
 * @brief Mix the columns of the given 4 nibbles, used for decryption
 *        using galois field matrix multiplication
 *
 * @param block
 */
void inv_mix_cols(i16_t *block) {

    static i8_t _tab[4] = {9, 2, 2, 9};

    _mat_mul(_tab, block);
}

/* Round constants for two rounds */
#define R_CON_1 0x80
#define R_CON_2 0x30

/**
 * @brief Find the temporary word given the previous word and the round constant
 *
 * @param w
 * @param r_con
 * @return i8_t
 */
static i8_t _find_tmp_word(i8_t w, i8_t r_con) {

    i8_t tmp;
    i8_t row;
    i8_t col;

    /* Substitution box table */
    static i8_t _tab[4][4] = {
        {9, 4, 10, 11},
        {13, 1, 8, 5},
        {6, 2, 0, 3},
        {12, 14, 15, 7}
    };

    /* Rotate the nibbles of the given word */
    tmp = ((w & 0x0F) << 4) | ((w & 0xF0) >> 4);

    /* Substitute the first nibble */
    row = (tmp & 0x0C) >> 2;
    col = (tmp & 0x03);
    tmp = (tmp & 0xF0);
    tmp = (tmp | _tab[row][col]);

    /* Substitute the second nibble */
    row = (tmp & 0xC0) >> 6;
    col = (tmp & 0x30) >> 4;
    tmp = (tmp & 0x0F);
    tmp = (tmp | _tab[row][col] << 4);

    /* Exor with the round constant */
    tmp = tmp ^ r_con;

    return tmp;
}

/**
 * @brief Expand the given 16 bit key into nibble arrays for each of the three
 *        subkeys
 *
 * @param key
 * @param subkey
 */
void key_exp(i16_t key, i32_t* subkey[0][3]) {

    i8_t w0;
    i8_t w1;
    i8_t w2;
    i8_t w3;
    i8_t w4;
    i8_t w5;
    i8_t t2;
    i8_t t4;

    /* Get the pre-round subkey */
    w0 = (key & 0xFF00) >> 8;
    w1 = (key & 0x00FF);
    /* Get thefirst round subkey */
    t2 = _find_tmp_word(w1, R_CON_1);
    w2 = t2 ^ w0;
    w3 = w2 ^ w1;
    /* Get the second round subkey */
    t4 = _find_tmp_word(w3, R_CON_2);
    w4 = t4 ^ w2;
    w5 = w4 ^ w3;
subkey[0][0]=(w0<<8)|w1;
subkey[0][1]=(w2<<8)|w3;
subkey[0][2]=(w4<<8)|w5;


}/**
 * @brief Return the galois field addition of a and b in GF(2^4)
 *
 * @param a
 * @param b
 * @return i8_t
 */
i8_t gf_add(i8_t c, i8_t d) {

    return (c & 0x0F) ^ (d & 0x0F);
}

/**
 * @brief Return the galois field multiplication of a and b in GF(2^4)
 *
 * @param a
 * @param b
 * @return i8_t
 */
i8_t gf_mul(i8_t a, i8_t b) {

    i8_t p = 0;

    /* Mask the unwanted bits */
    a = a & 0x0F;
    b = b & 0x0F;

    /* While both the multiplicands are non-zero */
    while (a && b) {

        /* If LSB of b is 1 */
        if (b & 1) {

            /* Add the current a to p */
            p = p ^ a;
        }

        /* Update both a and b */
        a = a << 1;
        b = b >> 1;

        /* If a overflows beyond the 4th bit */
        if (a & (1 << GF_DEGREE)) {

            a = a ^ GF_REDUCING_POLY;
        }
    }

    return p;
}
/**
 * @brief Encrypt a 16 bit block of plaintext
 *
 * @param plainblock
 * @param subkey
 * @return i16_t
 */
i16_t _saes_enc_block(i16_t* plainblock, i8_t* subkey[0][3]) {


    i16_t* block;
    block=plainblock;

    /* Pre-round */

    /* Add round key */
    add_rnd_key(block, &subkey[0][0]);

    /* Round 1 */

    /* Substitution */
    sub_nibbles(block);

    /* Shift rows */
    shft_rows(block);
    /* Mix columns */
    mix_cols(block);
    /* Add round key */
    add_rnd_key(block, &subkey[0][1]);

    /* Round 2 */

    /* Substitution */
    sub_nibbles(block);
    /* Shift rows */
    shft_rows(block);
    /* Add round key */
    add_rnd_key(block, &subkey[0][2]);


            return *block;
}

/**
 * @brief Decrypt a 16 bit block of ciphertext
 *
 * @param cipherblock
 * @param subkey
 * @return i16_t
 */
i16_t _saes_dec_block(i16_t* cipherblock, i8_t* subkey[0][3]) {


    i16_t* block;
    block=cipherblock;
    /* Pre-round */
    /* Add round key */
    add_rnd_key(block, &subkey[0][2]);


    /* First round */

    /* Inverse shift rows */
    shft_rows(block);

    /* Inverse substitution */
    inv_sub_nibbles(block);

    /* Add round key */
    add_rnd_key(block, &subkey[0][1]);
    /* Inverse mix columns */
    inv_mix_cols(block);

    /* Second round */

    /* Inverse shift rows */
      shft_rows(block);
    /* Inverse substitution */
    inv_sub_nibbles(block);
    /* Add round key */
    add_rnd_key(block, &subkey[0][0]);


    /* Combine the 4 nibbles and return the 16 bits */
     return *block;
}

/**
 * @brief Encrypt the given plaintext message to the ciphertext
 *
 * @param plaintext
 * @param ciphertext
 * @param size
 * @param key
 */
void saes_encrypt(i4_t *plaintext, i4_t *ciphertext, i64_t size, i16_t key) {

    i32_t subkey[0][3];
    i16_t *plainblock;
     plainblock = ((plaintext[0])<<12)|((plaintext[1])<<8)|((plaintext[2])<<4)|((plaintext[3]));
    i16_t *cipherblock =(i16_t *)ciphertext;
    /* Generate the subkeys */
    key_exp(key, subkey);
    cipherblock= _saes_enc_block(&plainblock, subkey);
    printf("ciphertext is  %X \n",cipherblock);

}

/**
 * @brief Decrypt the given ciphertext message to the plaintext
 *
 * @param ciphertext
 * @param plaintext
 * @param size
 * @param key
 */
void saes_decrypt(i8_t *ciphertext, i8_t *plaintext, i64_t size, i16_t key) {

    i8_t subkey[3][4];
    i16_t *plainblock = (i16_t *)plaintext;

    i16_t *cipherblock ;
     cipherblock = ((ciphertext[0])<<12)|((ciphertext[1])<<8)|((ciphertext[2])<<4)|((ciphertext[3]));

    /* Generate the subkeys */
    key_exp(key, subkey);

    /* Encrypt block by block */
    plainblock = _saes_dec_block(&cipherblock, subkey);
     printf("plaintext is  %X ",plainblock);

}


