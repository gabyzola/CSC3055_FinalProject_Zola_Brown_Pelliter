package pqcrypto;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Base64;

import common.Config;
import common.Constants;
import blockchain.BlockchainManager;
import blockchain.FileMetadata;
import blockchain.Transaction;

/**
 * Manages server-side file storage and operations.
 */
public class FileManager {
    private String fileStorageDirectory;
    private CryptoManager cryptoManager;
    private BlockchainManager blockchainManager;
    private long maxFileSize;
    
    /**
     * Create a new FileManager instance
     * 
     * @param config Server configuration
     * @param cryptoManager Server's crypto manager
     * @param blockchainManager Blockchain manager
     * @throws IOException If directory creation fails
     */
    public FileManager(Config config, CryptoManager cryptoManager, BlockchainManager blockchainManager) throws IOException {
        this.cryptoManager = cryptoManager;
        this.blockchainManager = blockchainManager;
        this.fileStorageDirectory = config.getString("storage.file_storage_directory", "./stores/files");
        this.maxFileSize = config.getLong("security.max_file_size_mb", 10) * 1024 * 1024;
        
        // Create storage directory if it doesn't exist
        Files.createDirectories(Paths.get(fileStorageDirectory));
    }
    
    /**
     * Store an uploaded file
     * 
     * @param encryptedFileData Encrypted file data
     * @param fileMetadata Metadata of the file
     * @return True if storage successful
     * @throws Exception If storage fails
     */
    public boolean storeFile(byte[] encryptedFileData, FileMetadata fileMetadata) throws Exception {
        // Check file size
        if (encryptedFileData.length > maxFileSize) {
            throw new IOException("File exceeds maximum size limit");
        }
        
        // Create file path based on hash - use URL-safe encoding
        String fileHash = fileMetadata.getFileHash();
        String safeFileHash = fileHash.replace("/", "_").replace("+", "-").replace("=", "");
        String filePath = fileStorageDirectory + File.separator + safeFileHash;
        
        // Create parent directory if needed
        File file = new File(filePath);
        file.getParentFile().mkdirs();
        
        // Save file
        try (FileOutputStream fos = new FileOutputStream(filePath)) {
            fos.write(encryptedFileData);
            fos.flush();
        }
        
        return true;
    }
    
    /**
     * Retrieve a stored file
     * 
     * @param fileHash Hash of the file to retrieve
     * @return Encrypted file data or null if not found
     * @throws IOException If retrieval fails
     */
    public byte[] retrieveFile(String fileHash) throws IOException {
        String safeFileHash = fileHash.replace("/", "_").replace("+", "-").replace("=", "");
        String filePath = fileStorageDirectory + File.separator + safeFileHash;
        File file = new File(filePath);
        
        if (!file.exists() || !file.isFile()) {
            return null;
        }
        
        // Read file
        return Files.readAllBytes(file.toPath());
    }
    
    /**
     * Check if a file exists
     * 
     * @param fileHash Hash of the file to check
     * @return True if file exists
     */
    public boolean fileExists(String fileHash) {
        String safeFileHash = fileHash.replace("/", "_").replace("+", "-").replace("=", "");
        String filePath = fileStorageDirectory + File.separator + safeFileHash;
        File file = new File(filePath);
        return file.exists() && file.isFile();
    }
    
    /**
     * Compute the hash of file data
     * 
     * @param fileData The file data to hash
     * @return Base64-encoded hash
     * @throws Exception If hashing fails
     */
    public String computeFileHash(byte[] fileData) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(Constants.HASH_ALGORITHM);
        byte[] hashBytes = digest.digest(fileData);
        return Base64.getEncoder().encodeToString(hashBytes);
    }
    
    /**
     * Verify file integrity against the blockchain
     * 
     * @param fileHash Hash of the file to verify
     * @return Transaction containing file metadata or null if not found
     */
    public Transaction verifyFileInBlockchain(String fileHash) {
        return blockchainManager.verifyFile(fileHash);
    }
    
    /**
     * Delete a file from storage
     * 
     * @param fileHash Hash of the file to delete
     * @return True if deletion successful
     */
    public boolean deleteFile(String fileHash) {
        String safeFileHash = fileHash.replace("/", "_").replace("+", "-").replace("=", "");
    String filePath = fileStorageDirectory + File.separator + safeFileHash;
        File file = new File(filePath);
        
        if (file.exists() && file.isFile()) {
            return file.delete();
        }
        
        return false;
    }
}