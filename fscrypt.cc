/* 
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

// Helper function for Xor operation of 8 bytes char arrays
void myXor(unsigned char* left, char* right, char* out);
	
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
	char* plainText;

	// Memmory allocated for cipher text
	int padLength = 0; 
	unsigned char* out;
	if (plainTextLength % BLOCKSIZE == 0) out = (unsigned char*) malloc(plainTextLength);
	else
	{
		padLength = BLOCKSIZE - (plainTextLength % BLOCKSIZE);
		out = (unsigned char*) malloc(plainTextLength + padLength);
		char p = '0' + padLength;		
		
		plainText = (char*) malloc(plainTextLength + padLength);

		// Plain text padded with length of the blank bytes in last block
		for (int j = 0; j < plainTextLength; j++) plainText[j] = pText[j];
		for (int n = 0; n < padLength; n++) plainText[plainTextLength + n] = p;
	}		

	unsigned char previousCipherBlock[8] = {0};	
	char plainTextBlock[8] = {0};
	unsigned char cipherTextBlock[8] = {0};	
	char myXorResult[8];
	double bSize = (double)	BLOCKSIZE;

	// Encription takes place here
	for (int i = 0; i < ceil(plainTextLength / bSize); i++)
	{
		for (int k = 0; k < BLOCKSIZE; k++) plainTextBlock[k] = plainText[(i * 8) + k];

		// IV should be used in first iteration
		if (i == 0) myXor(IV, plainTextBlock, myXorResult);
		else myXor(previousCipherBlock, plainTextBlock, myXorResult);
			
		const unsigned char* constXorResult = (const unsigned char*) myXorResult;
		BF_ecb_encrypt( constXorResult, cipherTextBlock, key, BF_ENCRYPT);

		for (int j = 0; j < BLOCKSIZE; j++)
		{
			previousCipherBlock[j] = cipherTextBlock[j];
			out[(i * 8) + j] = cipherTextBlock[j];
		}
	}
	
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
	unsigned char* out;
	out = (unsigned char*) malloc(bufsize);

	char* cipherText = (char*) ciphertext;	
	double bSize = (double)	BLOCKSIZE;
	unsigned char previousCipherBlock[8] = {0};
	unsigned char cipherTextBlock[8] = {0};

	// Decryption takes place here
	for (int i = 0; i < ceil(bufsize / bSize); i++)
	{
		for (int k = 0; k < BLOCKSIZE; k++) cipherTextBlock[k] = cipherText[(i * 8) + k];

		const unsigned char* constCipherTextBlock = (const unsigned char*) cipherTextBlock;
		unsigned char plainTextBlock[8] = {0};
		BF_ecb_encrypt(constCipherTextBlock, plainTextBlock, key, BF_DECRYPT);
		char* plainTextBlockForXor = (char*) plainTextBlock;
		char myXorResult[8];

		if (i == 0) myXor(IV, plainTextBlockForXor, myXorResult);
		else myXor(previousCipherBlock, plainTextBlockForXor, myXorResult);

		for (int j = 0; j < BLOCKSIZE; j++) 
		{
			out[(i * 8) + j] = myXorResult[j];
			previousCipherBlock[j] = cipherText[(i * 8) + j];		
		}
	}	

	unsigned char* result = (unsigned char*) malloc(bufsize);
	for (int k = 0; k < bufsize; k++) result[k] = out[k];

	return result;
}

// Bitwise XOR operation for char arrays of 8 byte
void myXor(unsigned char* left, char* right, char* out)
{
	for (int i = 0; i < BLOCKSIZE; i++) out[i] = left[i] ^ right[i];
}
