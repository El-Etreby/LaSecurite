package com.socket;
import java.io.UnsupportedEncodingException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class Encryptor {
	
	private String text=null;
	
	public Encryptor(String Action, String key, String initVector, String value)
	{
		if(Action=="en"){
			text= encrypt(key, initVector, value);
		}else{
			text= decrypt(key, initVector, value);
		}
		
	}
	
	
	
	
    public String getText() {
		return text;
	}




	public static String encrypt(String key, String initVector, String value) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            byte[] encrypted = cipher.doFinal(value.getBytes());
            System.out.println("encrypted string: "
                    + Base64.encodeBase64String(encrypted));

            return Base64.encodeBase64String(encrypted);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public static String decrypt(String key, String initVector, String encrypted) {
        try {
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
            SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

            byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));

            return new String(original);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    
    private static byte[] shortenSecretKey(final byte[] longKey) {

        try {

            // Use 8 bytes (64 bits) for DES, 6 bytes (48 bits) for Blowfish
            final byte[] shortenedKey = new byte[12];

            System.arraycopy(longKey, 0, shortenedKey, 0, shortenedKey.length);

            return shortenedKey;

            // Below lines can be more secure
            // final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
            // final DESKeySpec       desSpec    = new DESKeySpec(longKey);
            //
            // return keyFactory.generateSecret(desSpec).getEncoded();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
    
    
    
    
    public static void main(String[] args) throws UnsupportedEncodingException {
    	
    	
    	
    	 PrivateKey privateKey = null;
          PublicKey  publicKey;
          PublicKey  receivedPublicKey = null;
         byte[]   secretKey = null;
    	
    	
         try {
             final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
             keyPairGenerator.initialize(1024);

             final KeyPair keyPair = keyPairGenerator.generateKeyPair();

             privateKey = keyPair.getPrivate();
             publicKey  = keyPair.getPublic();
         } catch (Exception e) {
             e.printStackTrace();
         }
         try {
             final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
             keyPairGenerator.initialize(1024);

             final KeyPair keyPair = keyPairGenerator.generateKeyPair();

             
             receivedPublicKey  = keyPair.getPublic();
         } catch (Exception e) {
             e.printStackTrace();
         }
         
         try {
             final KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
             keyAgreement.init(privateKey);
             keyAgreement.doPhase(receivedPublicKey, true);

             secretKey = shortenSecretKey(keyAgreement.generateSecret());
         } catch (Exception e) {
             e.printStackTrace();
         }
    	
    	
    	System.out.println("the secret key is----->"+new String(secretKey));
    	
    	
    	String base64 = new String(Base64.encodeBase64(secretKey));
    	System.out.println("will it work--->"+base64);
    	
    	
    	
        String key = "Bar12345Bar12345"; // 128 bit key
        String initVector = "RandomInitVector"; // 16 bytes IV
        String en = encrypt(base64, initVector, "this is lola palooza for the rescue and we are here trying to reach out for help");
        System.out.println("encryoted-------->"+en );
        String de = decrypt(base64, initVector, en);
        System.out.println("decryoted-------->"+de );
        
        
        
//        System.out.println(decrypt(base64, initVector,
//                encrypt(base64, initVector, "Hello World")));
    }
}