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
        
        // CORRECT SERVER-COMPATIBLE APPROACH
        // This exactly matches how the server encrypts files in ClientHandler.java 
        try {
            System.out.println("SERVER-COMPATIBLE DECRYPTION - Using correct parameters");
            
            // Decode the parameters - IMPORTANT: Use fileIv, not iv!
            byte[] encryptedFileBytes = Base64.getDecoder().decode(encryptedData);
            byte[] ivBytes = Base64.getDecoder().decode(fileIv);  // fileIv is what matters!
            byte[] keyBytes = Base64.getDecoder().decode(encryptedSymmetricKey);
            
            System.out.println("Using correct decryption parameters:");
            System.out.println("- Key length: " + keyBytes.length + " bytes");
            System.out.println("- IV length: " + ivBytes.length + " bytes");
            System.out.println("- Encrypted data length: " + encryptedFileBytes.length + " bytes");
            
            // Create cipher with exact same parameters as server
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKey key = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
            
            // Perform decryption
            byte[] decryptedData = cipher.doFinal(encryptedFileBytes);
            System.out.println("Server-compatible decryption successful! Got " + decryptedData.length + " bytes");
            
            // Let's verify if this looks like text
            boolean isText = true;
            for (int i = 0; i < Math.min(decryptedData.length, 100); i++) {
                if (decryptedData[i] < 9 || (decryptedData[i] > 13 && decryptedData[i] < 32 && decryptedData[i] != 27)) {
                    isText = false;
                    break;
                }
            }
            
            if (isText) {
                try {
                    String text = new String(decryptedData, "UTF-8");
                    System.out.println("Decrypted data appears to be text: " + 
                        (text.length() > 50 ? text.substring(0, 50) + "..." : text));
                } catch (Exception e) {
                    System.out.println("Failed to convert decrypted data to text: " + e.getMessage());
                }
            } else {
                System.out.println("Decrypted data appears to be binary.");
            }
            
            return decryptedData;
        } catch (Exception e) {
            System.out.println("Server-compatible approach failed: " + e.getMessage());
            e.printStackTrace();
            System.out.println("Falling back to alternative decryption approaches...");
        }
        
        // We'll try multiple approaches in sequence as fallbacks
        Exception lastException = null;
        
        // Fallback approach 1: Try using the session IV (iv) instead of fileIv
        try {
            System.out.println("FALLBACK 1: Using session IV instead of fileIv");
            
            byte[] encryptedFileBytes = Base64.getDecoder().decode(encryptedData);
            byte[] ivBytes = Base64.getDecoder().decode(iv);  // Use session IV
            byte[] keyBytes = Base64.getDecoder().decode(encryptedSymmetricKey);
            
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            SecretKey key = new SecretKeySpec(keyBytes, "AES");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(128, ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, key, parameterSpec);
            
            byte[] decryptedData = cipher.doFinal(encryptedFileBytes);
            System.out.println("Fallback with session IV successful!");
            return decryptedData;
        } catch (Exception e) {
            System.out.println("FALLBACK 1 failed: " + e.getMessage());
            lastException = e;
        }
        
        // Fallback approach 2: Standard 3-step process with CryptoManager
        try {
            System.out.println("FALLBACK 2: Standard 3-step decryption process");
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
            System.out.println("FALLBACK 2 failed: " + e.getMessage());
            if (lastException == null) lastException = e;
        }
        
        // If all approaches failed, throw the last exception
        System.out.println("All decryption approaches failed!");
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
