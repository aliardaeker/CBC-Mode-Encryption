/* 
/	Ali Arda Eker
/	Enterprise Network Security Programing Assignment 1
/	Instructor: Guanhua Yan
/	Due date: February 15 
*/

#include "openssl/blowfish.h"

// Block size for blowfish.
const int BLOCKSIZE = 8;           

// Encrypt plaintext of length bufsize. Use keystr as the key.
void *fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen);

// Decrypt ciphertext of length bufsize. Use keystr as the key.
void *fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen);

