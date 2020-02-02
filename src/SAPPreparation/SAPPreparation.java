package SAPPreparation;

import java.security.Key;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class SAPPreparation {
	private static final String FILE_IN       = "test.txt";
	private static final String FILE_ECB_ENC  = "ecb.cipher.txt";
	private static final String FILE_ECB_DEC  = "ecb.plain.txt";
	private static final String FILE_CBC_ENC  = "cbc.cipher.txt";
	private static final String FILE_CBC_DEC  = "cbc.plain.txt";
	private static final String FILE_RSA_ENC  = "rsa.cipher.txt";
	private static final String FILE_RSA_DEC  = "rsa.plain.txt";
	private static final String FILE_CERT     = "ISMExamCert.cer";
	private static final String FILE_KEYSTORE = "ismkeystore.ks";
	private static final String PASS_KEYSTORE = "passks";
	private static final String PASS_AES      = "password12345678";
	
	// Convenience methods
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
	
	private static byte [] getNewKey(int len) throws NoSuchAlgorithmException {
		KeyGenerator keygen = KeyGenerator.getInstance("AES");
		keygen.init(len);
		return keygen.generateKey().getEncoded();
	}
	
	
	// Hashes
	private static byte [] md5(String file) throws NoSuchAlgorithmException, IOException {
		MessageDigest md5 = MessageDigest.getInstance("MD5");
		byte [] content = Files.readAllBytes(Paths.get(file));
		md5.update(content, 0, content.length);
		byte [] hash = md5.digest();
		return hash;
	}
	
	private static byte [] sha1(String file) throws NoSuchAlgorithmException, IOException {
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		byte [] content = Files.readAllBytes(Paths.get(file));
		sha1.update(content, 0, content.length);
		byte [] hash = sha1.digest();
		return hash;
	}
	
	private static byte [] sha256(String file) throws IOException, NoSuchAlgorithmException {
		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		byte [] content = Files.readAllBytes(Paths.get(file));
		sha256.update(content, 0, content.length);
		byte [] hash = sha256.digest();
		return hash;
	}
	
	
	// AES 
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
		// Read IV first - first 16 bytes of file
		for(int i = 0; i < iv.length; i++) {
			iv[i] = content[i];
		}
		// Rest is payload
		for(int i = iv.length; i < content.length; i++) {
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
	
	private static void decryptECB(String file, String outFile, String key) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte [] content = Files.readAllBytes(Paths.get(file));
		byte [] keyBytes = key.getBytes();
		Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
		SecretKeySpec secret = new SecretKeySpec(keyBytes, "AES");
		cipher.init(Cipher.DECRYPT_MODE, secret);
		byte[] output = cipher.doFinal(content);
		writeFile(outFile, output);
	}
	
	
	// X.509
	private static void printKeyStore(String fileName, String pass) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
		FileInputStream file = new FileInputStream(new File(fileName));
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(file, pass.toCharArray());
		
		//print the content
		Enumeration<String> aliases =  keyStore.aliases();
		while(aliases.hasMoreElements()) {
			String alias = aliases.nextElement();
			String type = "other";
			if(keyStore.isKeyEntry(alias)) {
				type = "key pair";
			} else if(keyStore.isCertificateEntry(alias)) {
				type = "certificate";
			}
			System.out.println(String.format("alias=%s, nature=%s", alias, type));
		}
		file.close();
	}
	
	
	private static PublicKey getCertificateKey(String fileName) throws CertificateException, FileNotFoundException {
		FileInputStream file = new FileInputStream(new File(fileName));
		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate) certFactory.generateCertificate(file);
		return cert.getPublicKey();
	}
	
	
	// RSA
	private static void encryptRSA(String file, String outFile, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
		byte [] contents = Files.readAllBytes(Paths.get(file));
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		byte [] output = cipher.doFinal(contents);
		printHex(output);
		writeFile(outFile, output);
	}
	
	private static void decryptRSA(String file, String outFile, Key key) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte [] contents = Files.readAllBytes(Paths.get(file));
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, key);
		byte [] output = cipher.doFinal(contents);
		printHex(output);
		writeFile(outFile, output);
	}
	
	private static PublicKey keyStoreGetPublicKey(String fileName, String pass, String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		FileInputStream file = new FileInputStream(new File(fileName));
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(file, pass.toCharArray());
		file.close();
		return (PublicKey) keyStore.getCertificate(alias).getPublicKey();
	}
	
	private static PrivateKey keyStoreGetPrivateKey(String fileName, String pass, String alias, String keyPass) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		FileInputStream file = new FileInputStream(new File(fileName));
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(file, pass.toCharArray());
		file.close();
		return (PrivateKey) keyStore.getKey(alias, keyPass.toCharArray());
	}
	
	
	// Signature
	private static byte [] getSignature(String fileName, PrivateKey priv) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
		// To make sure the file is yours, sign it with your private key
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(priv);
		byte[] contents = Files.readAllBytes(Paths.get(fileName));
		signature.update(contents, 0, contents.length);
		return signature.sign();
	}
	
	private static boolean verifySignature(String fileName, PublicKey pub, byte [] signature) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
		// To verify file was signed by you, one will validate with
		// your public key
		Signature verifier = Signature.getInstance("SHA1withRSA");
		verifier.initVerify(pub);
		byte[] contents = Files.readAllBytes(Paths.get(fileName));
		verifier.update(contents, 0, contents.length);
		return verifier.verify(signature);
	}
	
	public static void main(String[] args) {
		try {
			// Hashes/HMACs
			System.out.println("MD5: ");
			byte [] md5 = md5(FILE_IN);
			printHex(md5);
			
			System.out.println("SHA1: ");
			byte [] sha1 = sha1(FILE_IN);
			printHex(sha1);
			
			System.out.println("SHA256: ");
			byte [] sha256 = sha256(FILE_IN);
			printHex(sha256);
			
			// AES
			System.out.println("Encrypting with ECB...");
			encryptECB(FILE_IN, FILE_ECB_ENC, PASS_AES);
			
			System.out.println("Decrypting with ECB...");
			decryptECB(FILE_ECB_ENC, FILE_ECB_DEC, PASS_AES);
			
			System.out.println("Encrypting with CBC...");
			encryptCBC(FILE_IN, FILE_CBC_ENC, PASS_AES);
			
			System.out.println("Decrypting with CBC...");
			decryptCBC(FILE_CBC_ENC, FILE_CBC_DEC, PASS_AES);
			
			// X.509
			System.out.print("Keystore ");
			printKeyStore(FILE_KEYSTORE, PASS_KEYSTORE);
			
			// RSA
			PublicKey certKey = getCertificateKey(FILE_CERT);
			System.out.println(certKey);
			
			PublicKey pub = keyStoreGetPublicKey(FILE_KEYSTORE, PASS_KEYSTORE, "ismkey1");
			System.out.println(pub);
			
			PrivateKey priv = keyStoreGetPrivateKey(FILE_KEYSTORE, PASS_KEYSTORE, "ismkey1", "passism1");
			System.out.println(priv);
			
			System.out.println("Encrypting with RSA...");
			encryptRSA(FILE_IN, FILE_RSA_ENC, pub);
			
			System.out.println("Decrypting with RSA...");
			decryptRSA(FILE_RSA_ENC, FILE_RSA_DEC, priv);
			
			// Signature
			byte [] key = getNewKey(128);
			printHex(key);
			
			byte [] signature = getSignature(FILE_IN, priv);
			if(verifySignature(FILE_IN, pub, signature)) {
				System.out.println("Verified!");
			} else {
				System.out.println("Verification failed!");
			}
			
			// TODO:: signature has to be done too
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
