package pqcrypto;

import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import common.Constants;

/**
 * Implements AES-GCM symmetric encryption for file contents.
 */
public class SymmetricCrypto {
    private static final int GCM_IV_LENGTH = 12; // 96 bits
    
    private SecureRandom random;
    
    /**
     * Create a new SymmetricCrypto instance
     */
    public SymmetricCrypto() {
        this.random = new SecureRandom();
    }
    
    /**
     * Generate a random AES key
     * 
     * @return Base64-encoded AES key
     * @throws Exception If AES algorithm is not available
     */
    public String generateKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(Constants.AES_KEY_SIZE);
        SecretKey key = keyGen.generateKey();
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
    
    /**
     * Encrypt data using AES-GCM
     * 
     * @param data The data to encrypt
     * @param keyBase64 Base64-encoded AES key
     * @param associatedData Optional associated data for GCM authentication (can be null)
     * @return EncryptionResult containing ciphertext and IV
     * @throws Exception If encryption fails
     */
    public EncryptionResult encrypt(byte[] data, String keyBase64, byte[] associatedData) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
        
        // Add debug information
        System.out.println("Encryption details:");
        System.out.println(" - Input data length: " + data.length + " bytes");
        System.out.println(" - Original key length: " + keyBytes.length + " bytes");
        
        // AES key must be 16, 24, or 32 bytes (128, 192, or 256 bits)
        // For AES-256, we need 32 bytes
        if (keyBytes.length != 32) {
            System.out.println(" - Adjusting key from " + keyBytes.length + " bytes to 32 bytes");
            // Adjust key length if needed
            byte[] adjustedKeyBytes = new byte[32];
            java.util.Arrays.fill(adjustedKeyBytes, (byte)0); // Fill with zeros
            System.arraycopy(keyBytes, 0, adjustedKeyBytes, 0, Math.min(keyBytes.length, 32));
            keyBytes = adjustedKeyBytes;
        }
        
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        
        // Generate a random IV for GCM mode
        byte[] iv = new byte[GCM_IV_LENGTH];
        random.nextBytes(iv);
        System.out.println(" - Generated IV length: " + iv.length + " bytes");
        
        GCMParameterSpec parameterSpec = new GCMParameterSpec(Constants.AES_GCM_TAG_LENGTH, iv);
        
        Cipher cipher = Cipher.getInstance(Constants.AES_MODE);
        cipher.init(Cipher.ENCRYPT_MODE, key, parameterSpec);
        
        if (associatedData != null) {
            System.out.println(" - Using associated data length: " + associatedData.length + " bytes");
            cipher.updateAAD(associatedData);
        } else {
            System.out.println(" - No associated data provided");
        }
        
        byte[] ciphertext = cipher.doFinal(data);
        System.out.println(" - Generated ciphertext length: " + ciphertext.length + " bytes");
        
        String ciphertextBase64 = Base64.getEncoder().encodeToString(ciphertext);
        String ivBase64 = Base64.getEncoder().encodeToString(iv);
        
        return new EncryptionResult(ciphertextBase64, ivBase64);
    }
    
    /**
     * Decrypt data using AES-GCM
     * 
     * @param ciphertextBase64 Base64-encoded ciphertext
     * @param keyBase64 Base64-encoded AES key
     * @param ivBase64 Base64-encoded IV
     * @param associatedData Optional associated data for GCM authentication (can be null)
     * @return Decrypted data
     * @throws Exception If decryption fails
     */
    public byte[] decrypt(String ciphertextBase64, String keyBase64, String ivBase64, byte[] associatedData) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyBase64);
        byte[] ciphertext = Base64.getDecoder().decode(ciphertextBase64);
        byte[] iv = Base64.getDecoder().decode(ivBase64);
        
        // Add debug information
        System.out.println("Decryption details:");
        System.out.println(" - Key length: " + keyBytes.length + " bytes");
        System.out.println(" - Ciphertext length: " + ciphertext.length + " bytes");
        System.out.println(" - IV length: " + iv.length + " bytes");
        
        // AES key must be 16, 24, or 32 bytes (128, 192, or 256 bits)
        // For AES-256, we need 32 bytes
        if (keyBytes.length != 32) {
            System.out.println(" - Adjusting key from " + keyBytes.length + " bytes to 32 bytes");
            // Adjust key length if needed
            byte[] adjustedKeyBytes = new byte[32];
            java.util.Arrays.fill(adjustedKeyBytes, (byte)0); // Fill with zeros
            System.arraycopy(keyBytes, 0, adjustedKeyBytes, 0, Math.min(keyBytes.length, 32));
            keyBytes = adjustedKeyBytes;
        }
        
        SecretKey key = new SecretKeySpec(keyBytes, "AES");
        
        try {
            GCMParameterSpec parameterSpec = new GCMParameterSpec(Constants.AES_GCM_TAG_LENGTH, iv);
            
            Cipher cipher = Cipher.getInstance(Constants.AES_MODE);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
            
            if (associatedData != null) {
                cipher.updateAAD(associatedData);
            }
            
            return cipher.doFinal(ciphertext);
        } catch (javax.crypto.AEADBadTagException e) {
            System.out.println("Authentication tag verification failed: " + e.getMessage());
            System.out.println("This indicates the key, IV, or ciphertext may be incorrect,");
            System.out.println("or the data was modified/corrupted during transmission.");
            
            // For debugging: Try without AAD if it was provided
            if (associatedData != null) {
                System.out.println("Retrying without AAD as fallback...");
                GCMParameterSpec parameterSpec = new GCMParameterSpec(Constants.AES_GCM_TAG_LENGTH, iv);
                Cipher cipher = Cipher.getInstance(Constants.AES_MODE);
                cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
                try {
                    return cipher.doFinal(ciphertext);
                } catch (Exception inner) {
                    System.out.println("Fallback also failed: " + inner.getMessage());
                    throw e; // Rethrow the original exception
                }
            } else {
                throw e;
            }
        }
    }
    
    /**
     * Class representing the result of AES-GCM encryption
     */
    public static class EncryptionResult {
        private String ciphertext;
        private String iv;
        
        public EncryptionResult(String ciphertext, String iv) {
            this.ciphertext = ciphertext;
            this.iv = iv;
        }
        
        public String getCiphertext() {
            return ciphertext;
        }
        
        public String getIv() {
            return iv;
        }
    }
}