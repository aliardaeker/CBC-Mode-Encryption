/* 
/	Bonus Part: BF_cbc_encrypt is used instead of BF_ecb_encrypt
/	Ali Arda Eker
/	Enterprise Network Security Programing Assignment 1
/	Instructor: Guanhua Yan
/	Due date: February 15 
*/

#include "fscrypt.h"
#include <iostream>
#include <cstring>
#include <stdlib.h> 
#include <math.h> 
using namespace std;
	
// Encrypt plaintext of length bufsize. Use keystr as the key.
void * fs_encrypt(void *plaintext, int bufsize, char *keystr, int *resultlen)
{
	// Initialization vector
	unsigned char IV[8] = {0};

	// Key Generation	
	BF_KEY key[strlen(keystr)];		
	BF_set_key(key, strlen(keystr), (const unsigned char*) keystr);

	// Length of the plain text calculated
	char* pText = (char*) plaintext;	
	int plainTextLength = strlen(pText);

	// Memmory allocated for cipher text
	unsigned char* out = (unsigned char*) malloc(plainTextLength);

	const unsigned char* in = (const unsigned char*) pText;

	// Encription takes place here
	BF_cbc_encrypt(in, out, (long) plainTextLength, key, IV, BF_ENCRYPT);
	
	// Number of valid bytes kept in resultlen
	*resultlen = plainTextLength;	

	return out;
}

// Decrypt ciphertext of length bufsize. Use keystr as the key.
void * fs_decrypt(void *ciphertext, int bufsize, char *keystr, int *resultlen)
{
	// Initialization vector
	unsigned char IV[8] = {0};

	// Key Generation	
	BF_KEY key[strlen(keystr)];		
	BF_set_key(key, strlen(keystr), (const unsigned char*) keystr);

	// Number of valid bytes kept in resultlen
	*resultlen = bufsize + 1;

	// Memmory allocated for plain text 
	unsigned char* out = (unsigned char*) malloc(bufsize);	

	const unsigned char* in = (const unsigned char*) ciphertext;

	// Decryption takes place here
	BF_cbc_encrypt(in, out, (long) bufsize, key, IV, BF_DECRYPT);

	return out;
}
