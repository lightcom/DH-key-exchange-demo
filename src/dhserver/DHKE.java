/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package dhserver;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;

/**
 *
 * @author light
 */
public class DHKE {
    
    public BigInteger p;
    public BigInteger g;
    private final int length;
    
    private PrivateKey privateKey;
    private PublicKey publicKey;
    
    String algorithm;
    private SecretKey secretKey;
    
    Cipher encipher;
    Cipher decipher;
    
    public DHKE(BigInteger pv, BigInteger gv, int lv) {
        p = pv;
        g = gv;
        length = lv;
        generateKeys();
    }
    
    public DHKE(int lv){
        length = lv;
        try{
            AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
            paramGen.init(length, new SecureRandom());
            AlgorithmParameters params = paramGen.generateParameters();
            DHParameterSpec dhSpec = (DHParameterSpec)params.getParameterSpec(DHParameterSpec.class);
            p = dhSpec.getP();
            g = dhSpec.getG();
            generateKeys();
        }
        catch(NoSuchAlgorithmException | InvalidParameterSpecException e){
            System.out.println("Exception: "+e.getMessage());
        }
    }
    
    private void generateKeys(){
        try{
            // Use the values to generate a key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
            DHParameterSpec dhSpec = new DHParameterSpec(p, g, length);
            keyGen.initialize(dhSpec);
            KeyPair keypair = keyGen.generateKeyPair();

            // Get the generated public and private keys
            privateKey = keypair.getPrivate();
            publicKey = keypair.getPublic();
            
        }
        catch(NoSuchAlgorithmException | InvalidAlgorithmParameterException e){
            System.out.println("Exception: "+e.getMessage());
        }
    }
    
    public byte[] getPublicKeyBytes(){
        return publicKey.getEncoded();
    }
    
    public void generateSecretKey(byte[] publicKeyBytes, String algo) throws InvalidKeySpecException {
        try{
            // Convert the public key bytes into a PublicKey object
            X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFact = KeyFactory.getInstance("DH");
            PublicKey publicKey = keyFact.generatePublic(x509KeySpec);

            // Prepare to generate the secret key with the private key and public key of the other party
            KeyAgreement ka = KeyAgreement.getInstance("DH");
            ka.init(privateKey);
            ka.doPhase(publicKey, true);

            // Specify the type of key to generate: HmacSHA1, Blowfish,HmacMD5,TripleDES,DESede,DES
            algorithm = algo;

            // Generate the secret key
            secretKey = ka.generateSecret(algorithm);
            
//            BASE64Encoder encoder = new BASE64Encoder();
//            System.out.println("SecretKey: "+encoder.encode(secretKey.getEncoded()));
            
            encipher = Cipher.getInstance(algorithm);
            decipher = Cipher.getInstance(algorithm);
            encipher.init(Cipher.ENCRYPT_MODE, secretKey);
            decipher.init(Cipher.DECRYPT_MODE, secretKey);
        }
        catch(java.security.NoSuchAlgorithmException | InvalidKeyException | javax.crypto.NoSuchPaddingException e){
            System.out.println("Exception: "+e);
        }
    }
    
    public String encrypt(String str) throws IllegalBlockSizeException {
        try {
            // Encode the string into bytes using utf-8
            byte[] utf8 = str.getBytes("UTF8");

            // Encrypt
            byte[] enc = encipher.doFinal(utf8);

            // Encode bytes to base64 to get a string
            return new sun.misc.BASE64Encoder().encode(enc);
        } 
        catch (javax.crypto.BadPaddingException | IllegalBlockSizeException | UnsupportedEncodingException e) {
            System.out.println("Exception: "+e.getMessage());
        }
        return null;
    }
    
    public String decrypt(String str) {
        try {
            // Decode base64 to get bytes
            byte[] dec = new sun.misc.BASE64Decoder().decodeBuffer(str);

            // Decrypt
            byte[] utf8 = decipher.doFinal(dec);

            // Decode using utf-8
            return new String(utf8, "UTF8");
        }  
        catch (javax.crypto.BadPaddingException | IllegalBlockSizeException | UnsupportedEncodingException e) {
            System.out.println("Exception: "+e.getMessage());
        }
        catch (IOException e) {
            System.out.println("Exception: "+e.getMessage());
        }
        return null;
    }
    
}
