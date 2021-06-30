package ro.ase.sap.erik.kovacs;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
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
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

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

public class Main {
	
	private static void printHex (byte [] bytes) {
		for (byte b : bytes) {
			System.out.printf("%02x", b);
		}
	}
	
	private static byte [] readFile (String filename) throws IOException {
		return Files.readAllBytes(Paths.get(filename));
	}
	
	private static void writeFile (String file, byte [] bytes) throws IOException {
		BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(new File(file)));
		out.write(bytes);
		out.close();
	}
	
	private static byte [] sha256 (String filename) throws NoSuchAlgorithmException, IOException {
		MessageDigest sha1 = MessageDigest.getInstance("SHA-256");
		byte [] content = readFile(filename);
		sha1.update(content, 0, content.length);
		byte [] hash = sha1.digest();
		return hash;
	}
	
	private static byte [] decryptAesCbc(String file, String key, byte[] iv) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte [] content = readFile(file);
		byte [] keyBytes = key.getBytes();
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		IvParameterSpec ivSpec = new IvParameterSpec(iv);
		SecretKeySpec secret = new SecretKeySpec(keyBytes, "AES");
		cipher.init(Cipher.DECRYPT_MODE, secret, ivSpec);
		byte[] output = cipher.doFinal(content);
		return output;
	}
	
	private static byte [] pbkdf (char [] chars, byte [] salt, int iterations, int size) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, size);
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        byte [] hash = skf.generateSecret(spec).getEncoded();
        return hash;
	}
	
	private static byte [] sign(String file, PrivateKey priv) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
		Signature signature = Signature.getInstance("SHA1withRSA");
		signature.initSign(priv);
		byte[] contents = Files.readAllBytes(Paths.get(file));
		signature.update(contents, 0, contents.length);
		return signature.sign();
	}
	
	private static boolean verify(String file, PublicKey pub, byte [] signature) throws NoSuchAlgorithmException, InvalidKeyException, IOException, SignatureException {
		Signature verifier = Signature.getInstance("SHA1withRSA");
		verifier.initVerify(pub);
		byte[] contents = Files.readAllBytes(Paths.get(file));
		verifier.update(contents, 0, contents.length);
		return verifier.verify(signature);
	}
	
	
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException, CertificateException, KeyStoreException, UnrecoverableKeyException, SignatureException {
		
		byte [] iv = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte)0b11111111, 0x00, 0x00, 0x00};
		
		// List dir
		String dir = "./userFiles";
		File file = new File(dir);
        String[] pathnames = file.list();
        String userFile = null;
        
        // find file with the proper hash
        for (String pathname : pathnames) {
        	byte [] hash = sha256(dir + "/" + pathname);
        	byte [] encoded = Base64.getEncoder().encode(hash);
        	String hashBase64 = new String(encoded);
        	// System.out.printf("%s: sha256 = %s\n", pathname, hashBase64);
        	if ("xc48atgbCtZvFaeoFI4uOkTMFEQhd+0DckBls/WFonY=".equals(hashBase64)) {
        		System.out.printf("File found: %s\n", pathname);
        		userFile = dir + "/" + pathname;
        		break;
        	}
        }
        
        // file found
        if (null != userFile) {
        	
        	byte [] passwordBytes = decryptAesCbc(userFile, "userfilepass@6%6", iv);
        	String password = new String(passwordBytes, "UTF-8");
        	System.out.printf("Password found: %s\n", password);
        	password = password + "ism2021";
        	
        	// create bbkdf hash
        	byte [] pbkdfHash = pbkdf(password.toCharArray(), "ism2021".getBytes(), 150, 8 * 20);
        	System.out.printf("PBKDF hash: ");
        	printHex(pbkdfHash);
        	System.out.println();
        	writeFile("pbkdf.bin", pbkdfHash);
        	
        	// keystore generated with alias=erik, password=password1234
        	FileInputStream fis = new FileInputStream(new File("keystore.jks"));
    		KeyStore keyStore = KeyStore.getInstance("JKS");
    		keyStore.load(fis, "password1234".toCharArray());
    		fis.close();
    		
    		// get both keys
    		PrivateKey priv = (PrivateKey) keyStore.getKey("erik", "password1234".toCharArray());
    		PublicKey pub = (PublicKey) keyStore.getCertificate("erik").getPublicKey();
    		
    		// sign 
    		byte [] signature = sign("pbkdf.bin", priv);
    		writeFile("pbkdf.sig", signature);
    		
    		// verify
    		if (verify("pbkdf.bin", pub, signature)) {
    			System.out.println("Signatures match!");
    		} else {
    			System.out.println("Unable to verify signature.");
    		}
        } else {
        	System.out.println("User file not found.");
        }
	}

}
