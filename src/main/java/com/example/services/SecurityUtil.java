package com.example.services;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.springframework.stereotype.Component;

@Component
public class SecurityUtil {

	
//	public SecretKey getKeyFromPassword(String password, String salt) throws 
//	NoSuchAlgorithmException, InvalidKeySpecException{
//		
//		SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
//		KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
//		SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
//		
//		return secret;
//	}
	
	public static String generateKeys() {
        SecureRandom rand = new SecureRandom();
		
		Long fib = Math.abs(rand.nextLong(10000000000000000L)) + System.currentTimeMillis();
		
		return fib.toString();
	}
	
	public IvParameterSpec generateIvSpec() {
		byte[] iv = new byte[16];
		new SecureRandom().nextBytes(iv);
		
		return new IvParameterSpec(iv);
	}
	
	
	public String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv) 
			throws NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
		
		Cipher cipher = Cipher.getInstance(algorithm);
		
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		
		byte[] cipherText = cipher.doFinal(input.getBytes());
		
		return Base64.getEncoder().encodeToString(cipherText);
	}
	
	
	public String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv)
			throws NoSuchPaddingException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidAlgorithmParameterException {
		
		Cipher cipher = Cipher.getInstance(algorithm);
		
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		
		byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
		
		return new String(plainText);
	}
}
