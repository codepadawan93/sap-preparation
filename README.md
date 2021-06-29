# sap-preparation
SAP (ASE) Exam preparation

Crypto operations with java.security.* and OpenSSL

## Setup for Java
Things should pretty much work out of the box!

## Setup for C (Visual Studio 2019)
1. Install OpenSSL version 1.0.1j x64
2. Open Visual Studion 2019 and create a new Visual C++ Console App
3. Select the target machine type as x64 from Configuration Manager
4. Open project properties
5. Go to C/C++ -> General -> Additional Include Directories and add the value "C:\OpenSSL-Win64\include"
6. Go to Linker -> General -> Additional Library Directories and add the value "C:\OpenSSL-Win64\lib"
7. Go to Linker -> Input -> Additional Dependencies and add the value "libeay32.lib"

## Demo for C
```c
#include <iostream>
#include <openssl/sha.h>
#include <openssl/aes.h>

int main()
{
    unsigned char * buffer = new unsigned char[SHA_DIGEST_LENGTH];
    unsigned char content[] = { 0x1, 0x2, 0x3 };
    SHA_CTX ctx;
    SHA_Init(&ctx);
    SHA_Update(&ctx, content, 3);
    SHA_Final(buffer, &ctx);

    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        printf("%02x", buffer[i]);
    }

    unsigned char* buffer2 = new unsigned char[16];
    unsigned char key[] = { 
        0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8,
        0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8 };
    unsigned char content2[] = { 
        0x1, 0x2, 0x3, 0x1, 0x2, 0x3, 0x1, 0x2,
        0x1, 0x2, 0x3, 0x1, 0x2, 0x3, 0x1, 0x2
    };
    unsigned char iv[] = {
       0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1,
       0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1
    };

    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey);
    AES_cbc_encrypt(content2, buffer2, 16, &aesKey, iv, AES_ENCRYPT);

    for (int i = 0; i < 16; i++) {
        printf("%02x", buffer2[i]);
    }
}
```

## Demo for Java
```java
package com.erko.sapPreparation.sapReExam;

import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SapReExam {

	public static void main(String[] args) {
		String content = "Test text for using in this code";		
		String key = "testpassword1234";
		byte[] iv = {
				0x01, 0x02, 0x04, 0x05, 0x01, 0x02, 0x04, 0x05,
				0x01, 0x02, 0x04, 0x05, 0x01, 0x02, 0x04, 0x05 };
		try {
			MessageDigest md = MessageDigest.getInstance("SHA1");
			md.update(content.getBytes());
			byte[] digest = md.digest();
			for(byte b : digest) {
				System.out.printf("%02x", b);
			}
			
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			SecretKeySpec secret = new SecretKeySpec(key.getBytes(), "AES");
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			cipher.init(Cipher.ENCRYPT_MODE, secret, ivSpec);
			byte[] ciphertext = cipher.doFinal(content.getBytes());
			System.out.println("\n");
			for(byte b : ciphertext) {
				System.out.printf("%02x", b);
			}
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
```

## Demo for keytool

Generate a JKS keystore with a keypair:

```bash
keytool -genkey -keyalg RSA -alias <alias> -keystore <filename>.jks -storepass <keystore password> -keypass <keypair password>
```

Generate an X509 certificate from the JKS:

```bash
keytool -exportcert -alias <alias> -keystore <filename>.jks -file <output filename>.cer
```
