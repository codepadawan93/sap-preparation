package sapReExamProject;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SAPReExamProject {

	private static void printHex(byte[] bytes) {
		for(byte b : bytes) {
			System.out.printf("%02x", b);
		}
	}
	
	private static byte[] readFile(String filename) throws IOException {
		byte [] content = Files.readAllBytes(Paths.get(filename));
		return content;
	}
	
	private static byte[] doSha1(String filename) throws IOException, NoSuchAlgorithmException {
		MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
		byte [] content = readFile(filename);
		sha1.update(content, 0, content.length);
		byte [] hash = sha1.digest();
		return hash;
	}
	
	private static byte[] doAesCbc(String filename, String key) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		byte[] contents = readFile(filename);
		byte[] keyBytes = key.getBytes();
		byte[] ivBytes = new byte[keyBytes.length];
		Random random = new Random();
		for(int i = 0; i < ivBytes.length; i++) {
			ivBytes[i] = (byte) random.nextInt(7);
		}
		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
		IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
		SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
		byte[] ciphertext = cipher.doFinal(contents);
		byte[] output = new byte[ivBytes.length + ciphertext.length];
		System.arraycopy(ivBytes, 0, output, 0, ivBytes.length);
		System.arraycopy(ciphertext, 0, output, ivBytes.length, ciphertext.length);
		return output;
	}
	
	public static void main(String[] args) {
		String key = "secretpassword12";
		try {
			System.out.println("\nSha1 of file:\n");
			byte[] sha1 = doSha1("./resources/textfile.txt");
			printHex(sha1);
			System.out.println("\nAES-CBC encrypted file:\n");
			byte[] aesCbc = doAesCbc("./resources/textfile.txt", key);
			printHex(aesCbc);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
