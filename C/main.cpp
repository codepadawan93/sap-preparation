#include <iostream>
#include <fstream>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/applink.c>
#include <openssl/rsa.h>
#include <openssl/pem.h>

namespace SAPPreparation {
	// convenience functions
	void writeFile(const char * file, unsigned char * contents) {
		std::ofstream out(file, std::ofstream::out | std::ofstream::binary);
		out << contents;
		out.close();
	}
	void writeFile(const char * file, char * contents) {
		std::ofstream out(file, std::ofstream::out | std::ofstream::binary);
		out << contents;
		out.close();
	}

	void printHex(unsigned char * bytes, int len) {
		for (int i = 0; i < len; i++) {
			std::printf("%02x", bytes[i]);
		}
	}

	char * readFile(const char * fileName, int &length) {
		std::ifstream in(fileName, std::ifstream::in | std::ifstream::binary);
		in.seekg(0, in.end);
		length = in.tellg();
		in.seekg(0, in.beg);

		char * buffer = new char[length];
		in.read(buffer, length);
		in.close();
		return buffer;
	}

	// Hashes
	unsigned char * md5(const char * fileName) {
		int length = 0;
		char * contents = readFile(fileName, length);
		MD5_CTX ctx;
		unsigned char * finalDigest = new unsigned char [MD5_DIGEST_LENGTH];
		MD5_Init(&ctx);
		MD5_Update(&ctx, contents, length);
		MD5_Final(finalDigest, &ctx);
		return finalDigest;
	}

	unsigned char * sha1(const char * fileName) {
		int length = 0;
		char * contents = readFile(fileName, length);
		SHA_CTX ctx;
		unsigned char * finalDigest = new unsigned char[SHA_DIGEST_LENGTH];
		SHA_Init(&ctx);
		SHA_Update(&ctx, contents, length);
		SHA_Final(finalDigest, &ctx);
		return finalDigest;
	}

	unsigned char * sha256(const char * fileName) {
		int length = 0;
		char * contents = readFile(fileName, length);
		SHA256_CTX ctx;
		unsigned char * finalDigest = new unsigned char[SHA256_DIGEST_LENGTH];
		SHA256_Init(&ctx);
		SHA256_Update(&ctx, contents, length);
		SHA256_Final(finalDigest, &ctx);
		return finalDigest;
	}

	void decryptECB(const char * fileName, const char * outFile, unsigned char * key) {
		int length = 0;
		char * contents = readFile(fileName, length);
		AES_KEY akey;
		int outLength = length % 16 == 0 ? length : (length / 16) * 16 + 16;
		unsigned char* output = new unsigned char[outLength];
		AES_set_decrypt_key(key, 128, &akey);
		AES_decrypt((unsigned char *)contents, output, &akey);
		writeFile(outFile, output);
	}

	void encryptECB(const char * fileName, const char * outFile, unsigned char * key) {
		int length = 0;
		char * contents = readFile(fileName, length);
		AES_KEY akey;
		int outLength = length % 16 == 0 ? length : (length / 16) * 16 + 16;
		unsigned char* output = new unsigned char [outLength];
		AES_set_encrypt_key(key, 128, &akey);
		AES_encrypt((unsigned char *)contents, output, &akey);
		writeFile(outFile, output);
	}

	void encryptCBC(const char * fileName, const char * outFile, unsigned char * key, unsigned char * iv) {
		int length = 0;
		char * contents = readFile(fileName, length);
		AES_KEY akey;
		int outLength = length % 16 == 0 ? length : (length / 16) * 16 + 16;
		// Have to copy the iv as AES_cbc_encrypt modifies it in-memory
		unsigned char ivCopy[16];
		for (int i = 0; i < 16; i++) {
			ivCopy[i] = iv[i];
		}
		unsigned char * output = new unsigned char[outLength];
		AES_set_encrypt_key(key, 128, &akey);
		AES_cbc_encrypt((unsigned char *)contents, output, length, &akey, ivCopy, AES_ENCRYPT);
		writeFile(outFile, output);
	}

	void decryptCBC(const char * fileName, const char * outFile, unsigned char * key, unsigned char * iv) {
		int length = 0;
		char * contents = readFile(fileName, length);
		AES_KEY akey;
		int outLength = length % 16 == 0 ? length : (length / 16) * 16 + 16;
		// Have to copy the iv as AES_cbc_encrypt modifies it in-memory
		unsigned char ivCopy[16];
		for (int i = 0; i < 16; i++) {
			ivCopy[i] = iv[i];
		}
		unsigned char* output = new unsigned char[outLength];
		AES_set_decrypt_key(key, 128, &akey);
		AES_cbc_encrypt((unsigned char *)contents, output, length, &akey, ivCopy, AES_DECRYPT);
		writeFile(outFile, output);
	}

	unsigned char * decryptRSA(const char * fileName, const char * pemFile) {
		int length = 0;
		char * contents = readFile(fileName, length);
		RSA* publicKey;
		publicKey = RSA_new();
		FILE* pem;
		pem = fopen(pemFile, "r");
		unsigned char* output = new unsigned char[5000];
		if (pem) {
			publicKey = PEM_read_RSAPublicKey(pem, NULL, NULL, NULL);
			RSA_public_decrypt(RSA_size(publicKey), (const unsigned char *)contents, output, publicKey, RSA_PKCS1_PADDING);
			fclose(pem);
		}
		return output;
	}
}

int main() {
	SAPPreparation::writeFile("test.txt", "Test-Test-Test12");
	
	std::cout << "MD5 : ";
	unsigned char * md5 = SAPPreparation::md5("test.txt");
	SAPPreparation::printHex(md5, MD5_DIGEST_LENGTH);
	
	std::cout << std::endl << "SHA1 : ";
	unsigned char * sha1 = SAPPreparation::sha1("test.txt");
	SAPPreparation::printHex(sha1, SHA_DIGEST_LENGTH);

	std::cout << std::endl << "SHA256 : ";
	unsigned char * sha256 = SAPPreparation::sha256("test.txt");
	SAPPreparation::printHex(sha256, SHA256_DIGEST_LENGTH);

	unsigned char key[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
	SAPPreparation::encryptECB("test.txt", "ecb.enc.txt", key);
	SAPPreparation::decryptECB("ecb.enc.txt", "ecb.dec.txt", key);

	unsigned char iv[16] = { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 };
	SAPPreparation::encryptCBC("test.txt", "cbc.enc.txt", key, iv);
	SAPPreparation::decryptCBC("cbc.enc.txt", "cbc.dec.txt", key, iv);
	
	unsigned char * messageDigest1 = SAPPreparation::decryptRSA("eSignSHA1.txt", "pubKeyFile.pem");
	std::cout << "\nRSA: ";
	SAPPreparation::printHex(messageDigest1, SHA_DIGEST_LENGTH);

	unsigned char * messageDigest2 = SAPPreparation::sha1("Message.txt");
	std::cout << "\nDIGEST: ";
	SAPPreparation::printHex(messageDigest2, SHA_DIGEST_LENGTH);
	return 0;
}