package client;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import common.Config;
import common.Constants;

/**
 * Handles file operations for the client.
 */
public class FileOperations {
    private Config config;
    private CryptoManager cryptoManager;
    private String downloadDirectory;
    
    /**
     * Create a new FileOperations instance
     * 
     * @param config Client configuration
     * @param cryptoManager Client's crypto manager
     */
    public FileOperations(Config config, CryptoManager cryptoManager) {
        this.config = config;
        this.cryptoManager = cryptoManager;
        this.downloadDirectory = config.getString("storage.download_directory", "./downloads");
        
        // Create download directory if it doesn't exist
        new File(downloadDirectory).mkdirs();
    }
    
    /**
     * Read a file into memory
     * 
     * @param file The file to read
     * @return The file data as a byte array
     * @throws IOException If reading fails
     */
    public byte[] readFile(File file) throws IOException {
        return Files.readAllBytes(file.toPath());
    }
    
    /**
     * Write data to a file
     * 
     * @param file The file to write to
     * @param data The data to write
     * @throws IOException If writing fails
     */
    public void writeFile(File file, byte[] data) throws IOException {
        // Create parent directory if needed
        if (!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }
        
        // Write file
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(data);
            fos.flush();
        }
    }
    
    /**
     * Compute the hash of a file
     * 
     * @param file The file to hash
     * @return Base64-encoded hash
     * @throws Exception If hashing fails
     */
    public String computeFileHash(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(Constants.HASH_ALGORITHM);
        byte[] buffer = new byte[8192];
        int bytesRead;
        
        try (FileInputStream fis = new FileInputStream(file)) {
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }
        
        byte[] hashBytes = digest.digest();
        return Base64.getEncoder().encodeToString(hashBytes);
    }
    
    /**
     * Compute the hash of file data
     * 
     * @param data The data to hash
     * @return Base64-encoded hash
     * @throws Exception If hashing fails
     */
    public String computeFileHash(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(Constants.HASH_ALGORITHM);
        byte[] hashBytes = digest.digest(data);
        return Base64.getEncoder().encodeToString(hashBytes);
    }
    
    /**
     * Decrypt a file downloaded from the server
     * 
     * @param encryptedData Base64-encoded encrypted file data
     * @param iv Base64-encoded IV used for session encryption
     * @param encryptedSymmetricKey Base64-encoded encrypted symmetric key
     * @param fileIv Base64-encoded IV used for file encryption
     * @return Decrypted file data
     * @throws Exception If decryption fails
     */
    public byte[] decryptFile(String encryptedData, String iv, 
                            String encryptedSymmetricKey, String fileIv) throws Exception {
        System.out.println("Decrypting file with:");
        System.out.println("- Encrypted data length: " + (encryptedData != null ? encryptedData.length() : "null"));
        System.out.println("- Session IV length: " + (iv != null ? iv.length() : "null"));
        System.out.println("- Encrypted symmetric key length: " + (encryptedSymmetricKey != null ? encryptedSymmetricKey.length() : "null"));
        System.out.println("- File IV length: " + (fileIv != null ? fileIv.length() : "null"));
        
        // NEW SIMPLIFIED APPROACH - ONE-STEP DECRYPTION
        try {
            System.out.println("SIMPLIFIED DIRECT DECRYPTION - New optimized approach");
            
            // Step 1: First decrypt the transport layer encryption using the simplified approach
            byte[] encryptedFileData = Base64.getDecoder().decode(encryptedData);
            byte[] ivBytes = Base64.getDecoder().decode(iv);
            byte[] keyBytes = Base64.getDecoder().decode(encryptedSymmetricKey);
            
            System.out.println("Using temporary key directly for decryption");
            System.out.println("Temp key length: " + keyBytes.length + " bytes");
            System.out.println("IV length: " + ivBytes.length + " bytes");
            System.out.println("Encrypted data length: " + encryptedFileData.length + " bytes");
            
            // Create cipher for first-level decryption
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKey key = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
            
            // Decrypt first layer - this gives us the file content directly
            byte[] finalData = cipher.doFinal(encryptedFileData);
            System.out.println("Direct decryption successful! Got " + finalData.length + " bytes");
            
            // Let's verify if this looks like text
            boolean isText = true;
            for (int i = 0; i < Math.min(finalData.length, 100); i++) {
                if (finalData[i] < 9 || (finalData[i] > 13 && finalData[i] < 32 && finalData[i] != 27)) {
                    isText = false;
                    break;
                }
            }
            
            if (isText) {
                try {
                    String text = new String(finalData, "UTF-8");
                    System.out.println("Decrypted data appears to be text: " + 
                        (text.length() > 50 ? text.substring(0, 50) + "..." : text));
                } catch (Exception e) {
                    System.out.println("Failed to convert decrypted data to text: " + e.getMessage());
                }
            } else {
                System.out.println("Decrypted data appears to be binary. This may indicate the server still sent encrypted data.");
            }
            
            return finalData;
        } catch (Exception e) {
            System.out.println("Simplified approach failed: " + e.getMessage());
            System.out.println("Falling back to multiple decryption approaches...");
        }
        
        // We'll try multiple approaches in sequence as fallbacks
        Exception lastException = null;
        
        // Approach 1: Follow the standard 3-step process
        try {
            System.out.println("APPROACH 1: Standard 3-step decryption process");
            // First decrypt the encrypted data with the session key
            System.out.println("Step 1: Decrypting file data with session key");
            byte[] encryptedFileData = cryptoManager.decryptWithSessionKey(encryptedData, iv);
            System.out.println("Decrypted file data size: " + encryptedFileData.length + " bytes");
            
            // Then decrypt the symmetric key
            System.out.println("Step 2: Decrypting symmetric key");
            String symmetricKey = cryptoManager.decryptSymmetricKey(encryptedSymmetricKey);
            System.out.println("Symmetric key decrypted successfully");
            
            // Finally decrypt the file data with the symmetric key and file IV
            System.out.println("Step 3: Decrypting file data with symmetric key");
            byte[] decryptedData = cryptoManager.decryptWithSymmetricKey(encryptedFileData, symmetricKey, fileIv);
            System.out.println("Final decrypted file size: " + decryptedData.length + " bytes");
            return decryptedData;
        } catch (Exception e) {
            System.out.println("APPROACH 1 failed: " + e.getMessage());
            lastException = e;
        }
        
        // Approach 2: Try direct decryption of the encryptedData with the encryptedSymmetricKey
        try {
            System.out.println("APPROACH 2: Direct decryption with encrypted symmetric key");
            byte[] decryptedData = cryptoManager.decryptWithSymmetricKey(
                Base64.getDecoder().decode(encryptedData), 
                encryptedSymmetricKey, 
                fileIv
            );
            System.out.println("Direct decryption successful!");
            return decryptedData;
        } catch (Exception e) {
            System.out.println("APPROACH 2 failed: " + e.getMessage());
            if (lastException == null) lastException = e;
        }
        
        // Approach 3: Try using the session key directly for file decryption
        try {
            System.out.println("APPROACH 3: Using session key directly for file decryption");
            byte[] decryptedData = cryptoManager.decryptWithSessionKey(encryptedData, fileIv);
            System.out.println("Session key direct decryption successful!");
            return decryptedData;
        } catch (Exception e) {
            System.out.println("APPROACH 3 failed: " + e.getMessage());
            if (lastException == null) lastException = e;
        }
        
        // Approach 4: Try using simplified direct approach (GCM mode with direct key)
        try {
            System.out.println("APPROACH 4: Using simplified approach for direct GCM decryption");
            System.out.println("This should work with the server's new approach for downloads");
            
            byte[] encryptedFileData = Base64.getDecoder().decode(encryptedData);
            byte[] ivBytes = Base64.getDecoder().decode(fileIv);
            
            // Very important: We're not decoding the symmetric key because the server 
            // is now sending it as a plaintext Base64 string, not a Base64-encoded 
            // binary value that needs further decoding
            String keyStr = encryptedSymmetricKey;
            byte[] keyBytes = Base64.getDecoder().decode(keyStr);
            
            System.out.println("Using direct symmetric key: " + keyStr.substring(0, Math.min(10, keyStr.length())) + "...");
            System.out.println("Key bytes length: " + keyBytes.length);
            System.out.println("IV bytes length: " + ivBytes.length);
            System.out.println("Encrypted data length: " + encryptedFileData.length);
            
            // Create a cipher directly
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKey key = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
            
            // Decrypt data
            byte[] decryptedData = cipher.doFinal(encryptedFileData);
            System.out.println("Direct AES/GCM decryption successful!");
            return decryptedData;
        } catch (Exception e) {
            System.out.println("APPROACH 4 failed: " + e.getMessage());
            if (lastException == null) lastException = e;
        }
        
        // Approach 5: Try CBC mode with PKCS5Padding
        try {
            System.out.println("APPROACH 5: Using CBC mode with PKCS5Padding");
            
            byte[] encryptedFileData = Base64.getDecoder().decode(encryptedData);
            byte[] ivBytes = Base64.getDecoder().decode(fileIv);
            byte[] keyBytes = Base64.getDecoder().decode(encryptedSymmetricKey);
            
            // Adjust key length to 32 bytes for AES-256
            if (keyBytes.length != 32) {
                byte[] adjustedKey = new byte[32];
                Arrays.fill(adjustedKey, (byte)0);
                System.arraycopy(keyBytes, 0, adjustedKey, 0, Math.min(keyBytes.length, 32));
                keyBytes = adjustedKey;
                System.out.println("Adjusted key length to 32 bytes for CBC mode");
            }
            
            // Adjust IV length to 16 bytes for CBC (it needs exactly 16 bytes)
            if (ivBytes.length != 16) {
                byte[] adjustedIv = new byte[16];
                Arrays.fill(adjustedIv, (byte)0);
                System.arraycopy(ivBytes, 0, adjustedIv, 0, Math.min(ivBytes.length, 16));
                ivBytes = adjustedIv;
                System.out.println("Adjusted IV length to 16 bytes for CBC mode");
            }
            
            // Create a cipher using CBC mode
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKey key = new SecretKeySpec(keyBytes, "AES");
            javax.crypto.spec.IvParameterSpec ivSpec = new javax.crypto.spec.IvParameterSpec(ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
            
            // Decrypt data
            byte[] decryptedData = cipher.doFinal(encryptedFileData);
            System.out.println("Direct AES/CBC/PKCS5Padding decryption successful!");
            return decryptedData;
        } catch (Exception e) {
            System.out.println("APPROACH 5 failed: " + e.getMessage());
            if (lastException == null) lastException = e;
        }
        
        // If all approaches failed, throw the last exception
        System.out.println("All 5 decryption approaches failed!");
        throw lastException;
    }
    
    /**
     * Get hexadecimal representation of file content
     */
    private String getHexDump(byte[] data, int maxLength) {
        if (data == null) {
            return "null";
        }
        
        StringBuilder sb = new StringBuilder();
        sb.append("Size: ").append(data.length).append(" bytes\n");
        
        int length = Math.min(data.length, maxLength);
        for (int i = 0; i < length; i++) {
            String hex = Integer.toHexString(data[i] & 0xFF).toUpperCase();
            if (hex.length() == 1) {
                sb.append('0');
            }
            sb.append(hex);
            
            if ((i + 1) % 16 == 0) {
                sb.append("\n");
            } else {
                sb.append(' ');
            }
        }
        
        if (data.length > maxLength) {
            sb.append("... (truncated)");
        }
        
        return sb.toString();
    }
    
    /**
     * Get a simple debugging summary of the file content
     */
    public String getContentSummary(byte[] data) {
        if (data == null) {
            return "null";
        }
        
        // Try to detect if this is text
        boolean isText = true;
        for (int i = 0; i < Math.min(data.length, 100); i++) {
            if (data[i] < 9 || (data[i] > 13 && data[i] < 32 && data[i] != 27)) {
                isText = false;
                break;
            }
        }
        
        if (isText) {
            try {
                String text = new String(data, "UTF-8");
                return "Text content (" + data.length + " bytes): " + 
                       (text.length() > 100 ? text.substring(0, 100) + "..." : text);
            } catch (Exception e) {
                isText = false;
            }
        }
        
        // Otherwise show hex dump
        return "Binary content:\n" + getHexDump(data, 128);
    }
    }
