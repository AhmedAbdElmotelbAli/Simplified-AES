#include <stdio.h>
#include <stdlib.h>
#include "TYPES.h"
#include "AES.h"


/* Max plaintext/ciphertext message size in bytes */
#define MAX_TEXT_SIZE (96u)

/**
 * @brief Driver program for decrypting the ciphertext read from STDIN and print
 *        the plaintext to STDOUT. The key is taken as a command line argument
 *
 * @param argc
 * @param argv
 */
void main(int argc, char *argv[]) {


    i16_t temp;
    i4_t plaintext[MAX_TEXT_SIZE];
    i4_t ciphertext[MAX_TEXT_SIZE];
    i16_t key;
    i64_t size = 0;
    int f=0;
   // int d=0;
  //  scanf(" d is %d",d);
    if(argc < 4){
    fprintf(stderr,"option1 ENC\twrite 1\noption2 DES\twrite 2\n");
    fprintf(stderr,"Seas_1901401 ENC key is : ");
    }
    char *w = argv[1];
     key = (i16_t)strtol(argv[2], NULL, 16);
     temp = (i16_t)strtol(argv[3], NULL, 16);

//   plaintext=strtok(argv[3]);
    if(strcmp(w, "ENC") == 0||strcmp(w, "enc") == 0){
            f=2;
    plaintext[0]=(temp&0xf000)>>12;
    plaintext[1]=(temp&0x0f00)>>8;
    plaintext[2]=(temp&0x00f0)>>4;
    plaintext[3]=(temp&0x000f);
        /*  for(int i=0;i<4 ;i++){
                scanf("%1x",&plaintext[i]);
          }*/

           plaintext[4]='\0';
    }
    if(strcmp(w, "DEC") == 0||strcmp(w, "dec") == 0){
            f=1;

      //   scanf("%x",&key);

           ciphertext[0]=(temp&0xf000)>>12;
            ciphertext[1]=(temp&0x0f00)>>8;
            ciphertext[2]=(temp&0x00f0)>>4;
            ciphertext[3]=(temp&0x000f);
          /*  for(int i=0;i<4 ;i++){
                scanf("%1x",&ciphertext[i]);
          }*/
           ciphertext[4]='\0';

    }
    int i;
    if(f==2){
     /* Decrypt the ciphertext message */
    saes_encrypt(plaintext, ciphertext,strlen(ciphertext),key);
    }
    else if(f==1){
    saes_decrypt(ciphertext, plaintext, strlen(plaintext), key);
    }
}
//8F95C5C6
