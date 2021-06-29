package ro.ase.ism.kovacs.erik;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
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
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Enumeration;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


//Student | Base 64 hash value | File pass | IV
//KOVACS ERIK - ROBERT | xc48atgbCtZvFaeoFI4uOkTMFEQhd+0DckBls/WFonY= | userfilepass@6%6 | The 13th byte from left to right has all bits 1. The others are all 0

/**
* 
* 
* Each student will develop the solution in a single .java file and in a package that has his/her name
in it (ex: ro.ase.ism.lastname.firstname)
Each student will use the values given in the users.pdf file. Search for your name in that file.
PART I (10 points)
A DB admin asks for your help to update the hash value of a user in his/her database.
He sent you that user password in an encrypted file (with a .user extension). Search for that file as you
know its SHA256 hash value in Base64 format.
Print the designated file name at the console.
PART II (5 points)
Once you found the file, decrypt it (AES in CBC mode with a known IV - check the user’s file. There is
no need for Padding as the file has the required size) using the password sent by your friend (check
the users.pdf file).
The decrypted content represents the user password as a string with 16 characters.
Print the user password at the console.
PART III (5 points)
Add to the user password the "ism2021" salt at the end and hash it with the PBKDF (Password-Based
Key Derivation Function) based on HmacSHA1 algorithm with 150 iterations. The output must have
20 bytes.
Store the result in a binary file (you can choose the filename name). To get the points, the value must
be validated by your friend.
PART IV (5 points)
To assure your friend that no one is tampering with that value, digitally sign the previous binary file
with your public key. Store the signature in another binary file.
Using keytool generate a RSA pair. Export the public key in a X509 .cer file. Use the private key to sign
the previous file.
Send your colleague the binary files with the signature and your public certificate.
To get points the digital signature must be validated for the previous file with your public key.
Upload on Sakai
• The .java file with your solution (only 1 file)
• The binary file with the PBKDF hash value
• The binary file with the digital signature of the previous file
• The .cer file with your public key
* 
*/
public class SAPReExamYear2 {
	
	private static final String mySha = "xc48atgbCtZvFaeoFI4uOkTMFEQhd+0DckBls/WFonY=";
	private static final String myKey = "userfilepass@6%6";
	private static final byte [] myIv = new byte [16];
	private static final String myKeyStore = "keystore.jks";
	
	private static void printh(byte[] bytes) {
		for(byte b : bytes) {
			System.out.printf("%02x", b);
		}
	}
	
	private static String byteArrTob64 (byte [] bytes) {
		byte[] encoded = Base64.getEncoder().encode(bytes);
		return new String(encoded);
	}
	
	private static byte[] readFile(String filename) throws IOException {
		byte [] content = Files.readAllBytes(Paths.get(filename));
		return content;
	}
	
	private static void writeFile(String file, byte [] contents) throws IOException {
		BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(new File(file)));
		out.write(contents);
		out.close();
	}
	
	private static byte[] doSha(String filename) throws IOException, NoSuchAlgorithmException {
		MessageDigest sha1 = MessageDigest.getInstance("SHA-256");
		byte [] content = readFile(filename);
		sha1.update(content, 0, content.length);
		byte [] hash = sha1.digest();
		return hash;
	}
	
	private static byte [] decryptAesCbc(String file, String key, byte[] iv) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte [] content = Files.readAllBytes(Paths.get(file));
		byte [] keyBytes = key.getBytes();
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		SecretKeySpec secret = new SecretKeySpec(keyBytes, "AES");
		cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);
		byte[] output = cipher.doFinal(content);
		return output;
	}
	
	private static void printJks(String fileName, String pass) throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException {
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
	
	private static PrivateKey getPriv(String fileName, String pass, String alias, String keyPass) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		FileInputStream file = new FileInputStream(new File(fileName));
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(file, pass.toCharArray());
		file.close();
		return (PrivateKey) keyStore.getKey(alias, keyPass.toCharArray());
	}
	
	private static PublicKey getPub(String fileName, String pass, String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		FileInputStream file = new FileInputStream(new File(fileName));
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(file, pass.toCharArray());
		file.close();
		return (PublicKey) keyStore.getCertificate(alias).getPublicKey();
	}
	
	private static byte [] sign(String fileName, PrivateKey priv) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(priv);
		byte[] contents = Files.readAllBytes(Paths.get(fileName));
		signature.update(contents, 0, contents.length);
		return signature.sign();
	}
	
	private static boolean verify(String fileName, PublicKey pub, byte [] signature) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
		Signature verifier = Signature.getInstance("SHA1withRSA");
		verifier.initVerify(pub);
		byte[] contents = Files.readAllBytes(Paths.get(fileName));
		verifier.update(contents, 0, contents.length);
		return verifier.verify(signature);
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, CertificateException, KeyStoreException, UnrecoverableKeyException, SignatureException {
		
		// Setup IV
		for (int i = 0; i < 16; i ++) {			
			myIv[i] = (byte) ((i == 12) ? 0xff : 0x00);
		}
		
		// List dir userFiles
		String dir = "./userFiles";
		File file = new File(dir);
        String[] pathnames = file.list();
        String foundFile = null;
        
        // check sha against what we had
        for (String pathname : pathnames) {
        	String filePath = String.format("%s/%s", dir, pathname);
            byte[] sha = doSha(filePath);
            String b64 = byteArrTob64(sha);
            if (mySha.equals(b64)) {
            	foundFile = filePath;
            	System.out.printf("%s is the right file\n", pathname);
            }
        }
    
        String password = null;
        
        if (foundFile != null) {
        	byte [] decrypted = decryptAesCbc(foundFile, myKey, myIv);
        	password = new String(decrypted, StandardCharsets.UTF_8);
        	System.out.printf("%s is the password\n", password);
        }
        
        // Generate hash
        if (password != null) {
        	int iterations = 150;
            int size = 8 * 20;
            
            password = password + "ism2021";
        	char[] chars = password.toCharArray();
        	byte[] salt = "ism2021".getBytes();
        	
            PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, size);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] hash = skf.generateSecret(spec).getEncoded();
            System.out.printf("hash obtained is: ");
            printh(hash);
            System.out.printf("\n");
            writeFile("Erik.bin", hash);
            
            printJks(myKeyStore, "changeit");
            
            String kpAlias = "erik"; // Alias
            String kpPassword = "changeit"; // Default password
            
            // Get our generated private key and sign our .bin file with it
            PrivateKey priv = getPriv(myKeyStore, kpPassword, kpAlias, kpPassword);
            byte[] signature = sign("Erik.bin", priv);
            writeFile("Erik.sig", signature);
            
            // Verify it too
            PublicKey pub = getPub(myKeyStore, kpPassword, kpAlias);
            if(verify("Erik.bin", pub, signature)) {
            	System.out.println("Signature verified!");
            }
        }
	}
}