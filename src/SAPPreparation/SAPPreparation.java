package SAPPreparation;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class SAPPreparation {
	private static final String FILE_IN = "test.txt";
	private static final String FILE_ECB_ENC = "ecb.cipher.txt";
	private static final String FILE_ECB_DEC = "ecb.plain.txt";
	private static final String FILE_CBC_ENC = "cbc.cipher.txt";
	private static final String FILE_CBC_DEC = "cbc.plain.txt";
	private static final String ALG_AES = "AES";
	private static final String CERT_FILE = "ISMExamCert.cer";
	private static final String FILE_KEYSTORE = "examkeystore.ks";
	private static final String PASS_KEYSTORE = "Secret1234ABCDEF";
	
	private static void printHex(byte [] bytes) {
		for(byte b : bytes) {
			System.out.printf("%02x", b);
		}
		System.out.println();
	}
	
	private static void writeFile(String file, byte [] contents) throws IOException {
		BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(new File(file)));
		out.write(contents);
		out.close();
	}
	
	private static void md5(String file) throws NoSuchAlgorithmException, IOException {
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		byte [] content = Files.readAllBytes(Paths.get(file));
		md5.update(content, 0, content.length);
		byte [] hash = md5.digest();
		System.out.println(DatatypeConverter.printHexBinary(hash));
	}
	
	private static void sha1(String file) throws NoSuchAlgorithmException, IOException {
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		byte [] content = Files.readAllBytes(Paths.get(file));
		sha1.update(content, 0, content.length);
		byte [] hash = sha1.digest();
		System.out.println(DatatypeConverter.printHexBinary(hash));
	}
	
	private static void sha256(String file) throws IOException, NoSuchAlgorithmException {
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte [] content = Files.readAllBytes(Paths.get(file));
		sha256.update(content, 0, content.length);
		byte [] hash = sha256.digest();
		System.out.println(DatatypeConverter.printHexBinary(hash));
	}
	
	private static void encryptCBC(String file, String outFile, String key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException {
		byte [] content = Files.readAllBytes(Paths.get(file));
		byte [] keyBytes = key.getBytes();
		byte [] iv = new byte [keyBytes.length];
		Random random = new Random();
		for(int i = 0; i < iv.length; i++) {
			iv[i] = (byte) random.nextInt(7);
		}
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		SecretKeySpec secret = new SecretKeySpec(keyBytes, "AES");
		cipher.init(Cipher.ENCRYPT_MODE, secret, ivSpec);
		byte[] output = cipher.doFinal(content);
		byte [] ivAndContent = new byte[output.length + iv.length];
		for(int i = 0; i < iv.length; i++) {
			ivAndContent[i] = iv[i];
		}
		for(int i = 0; i < output.length; i++) {
			ivAndContent[i + iv.length] = output[i];
		}
		writeFile(outFile, ivAndContent);
	}
	
	private static void decryptCBC(String file, String outFile, String key) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte [] content = Files.readAllBytes(Paths.get(file));
		byte [] keyBytes = key.getBytes();
		byte [] iv = new byte [keyBytes.length];
		byte [] payloadContent = new byte[content.length - iv.length];
		int i = 0;
		for(; i < iv.length; i++) {
			iv[i] = content[i];
		}
		for(; i < content.length; i++) {
			payloadContent[i - iv.length] = content[i];
		}
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		SecretKeySpec secret = new SecretKeySpec(keyBytes, "AES");
		cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);
		byte[] output = cipher.doFinal(payloadContent);
		writeFile(outFile, output);
	}
	
	private static void encryptECB(String file, String outFile, String key) throws IllegalBlockSizeException, BadPaddingException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException {
		byte [] content = Files.readAllBytes(Paths.get(file));
		byte [] keyBytes = key.getBytes();
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
		SecretKeySpec secret = new SecretKeySpec(keyBytes, "AES");
		cipher.init(Cipher.ENCRYPT_MODE, secret);
		byte[] output = cipher.doFinal(content);
		writeFile(outFile, output);
	}
	
	private static void decryptECB(String key) {
		//
	}
	
	private static void rsa() {
		// TODO implement rsa
	}
	
	private static void x509seeKeyStore() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		FileInputStream file = new FileInputStream(new File(FILE_KEYSTORE));
		
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(file, PASS_KEYSTORE.toCharArray());
		
		//print the content
		Enumeration<String> aliases =  keyStore.aliases();
		while(aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			
			System.out.println("Keystore entry: " + alias);
			
			if(keyStore.isKeyEntry(alias)) {
				System.out.println("It's a priv & pub key entry");
			}
			
			if(keyStore.isCertificateEntry(alias)) {
				System.out.println("It's just a certificate");
			}
		}
		
		file.close();
	}
	
	
	private static PublicKey x509getPublicKey() throws CertificateException, FileNotFoundException {
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new FileInputStream(CERT_FILE));
		return cert.getPublicKey();
	}
	
	
	public static void main(String[] args) {
		try {
			// Hashes/HMACs
			System.out.println("MD5: ");
			md5(FILE_IN);
			System.out.println("SHA1: ");
			sha1(FILE_IN);
			System.out.println("SHA256: ");
			sha256(FILE_IN);
			
			// AES
			System.out.println("Encrypting with ECB...");
			encryptCBC(FILE_IN, FILE_ECB_ENC, "password12345678");
			System.out.println("Decrypting with ECB...");
			decryptCBC(FILE_ECB_ENC, FILE_ECB_DEC, "password12345678");
			System.out.println("Encrypting with CBC...");
			encryptCBC(FILE_IN, FILE_CBC_ENC, "password12345678");
			System.out.println("Decrypting with CBC...");
			decryptCBC(FILE_CBC_ENC, FILE_CBC_DEC, "password12345678");
			
			// RSA
			
			// X.509
			System.out.print("Keystore ");
//			x509seeKeyStore();
//			System.out.println(x509getPublicKey());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
