#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <fstream>
#include <openssl/sha.h>
#include <openssl/aes.h>

#define AES_KEY_LENGTH_BYTES 16

void printHex(unsigned char * bytes, int len) {
	for (int i = 0; i < len; i++) {
		printf("%02x", bytes[i]);
	}
}

unsigned char * readFile(const char * filename, int & len) {
	std::ifstream in(filename, std::ifstream::in | std::ifstream::binary);
	in.seekg(0, in.end);
	len = in.tellg();
	in.seekg(0, in.beg);

	char* buffer = new char[len];
	in.read(buffer, len);
	in.close();
	return (unsigned char *) buffer;
}

unsigned char * doSha1(const char * filename) {
	int len = 0;
	unsigned char * contents = readFile(filename, len);
	SHA_CTX ctx;
	unsigned char* digest = new unsigned char[SHA_DIGEST_LENGTH];
	SHA_Init(&ctx);
	SHA_Update(&ctx, contents, len);
	SHA_Final(digest, &ctx);
	return digest;
}

unsigned char * doAesCbc(const char * filename, const unsigned char * key, const unsigned char * iv, int & len) {
	len = 0;
	unsigned char* contents = readFile(filename, len);
	AES_KEY akey;
	len = len % AES_KEY_LENGTH_BYTES == 0 ? len : (len / AES_KEY_LENGTH_BYTES) * AES_KEY_LENGTH_BYTES + AES_KEY_LENGTH_BYTES;
	unsigned char* ciphertext = new unsigned char[len];
	for (int i = 0; i < len; i++) {
		ciphertext[i] = 0x00;
	}
	unsigned char * output = new unsigned char[len + AES_KEY_LENGTH_BYTES];
	unsigned char * ivCopy = new unsigned char[AES_KEY_LENGTH_BYTES];
	for (int i = 0; i < AES_KEY_LENGTH_BYTES; i++) {
		ivCopy[i] = iv[i];
		output[i] = iv[i];
	}
	AES_set_encrypt_key(key, 128, &akey);
	AES_cbc_encrypt(contents, ciphertext, len, &akey, ivCopy, AES_ENCRYPT);
	len += AES_KEY_LENGTH_BYTES;
	for (int i = AES_KEY_LENGTH_BYTES; i < len; i++) {
		output[i] = ciphertext[i - AES_KEY_LENGTH_BYTES];
	}
	return output;
}

int main() {
	unsigned char * sha1 = doSha1("./textfile.txt");
	printf("SHA1 value :\n");
	printHex(sha1, SHA_DIGEST_LENGTH);
	unsigned char * iv = new unsigned char[AES_KEY_LENGTH_BYTES];
	for (int i = 0; i < AES_KEY_LENGTH_BYTES; i++) {
		iv[i] = 0x01;
	}
	unsigned char key[] = { 
		0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x70, 0x61, 
		0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x31, 0x32 }; // secretpassword12
	int len;
	unsigned char * ciphertext = doAesCbc("./textfile.txt", key, iv, len);
	printf("\nCiphertext :\n");
	printHex(ciphertext, len);
}