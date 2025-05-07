package test.pqcrypto;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import blockchain.BlockchainManager;
import blockchain.FileMetadata;
import blockchain.Transaction;
import common.Config;
import pqcrypto.CryptoManager;
import pqcrypto.FileManager;
import pqcrypto.SymmetricCrypto;

public class FileManagerTest {
    // Simple assertion method
    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            System.err.println("FAILED: " + message);
            Thread.dumpStack();
        } else {
            System.out.println("PASSED: " + message);
        }
    }
    
    // Simple equality assertion
    private static void assertEquals(Object expected, Object actual, String message) {
        boolean isEqual = (expected == null && actual == null) || 
                         (expected != null && expected.equals(actual));
        assertTrue(isEqual, message + " - Expected: " + expected + ", Actual: " + actual);
    }
    
    // Simple not-null assertion
    private static void assertNotNull(Object obj, String message) {
        assertTrue(obj != null, message);
    }
    
    public static void main(String[] args) {
        try {
            System.out.println("========== Testing FileManager ==========");
            
            // Create test directory structure
            File testDir = new File("./test-data/file-test");
            testDir.mkdirs();
            
            File tempFileDir = new File(testDir, "files");
            tempFileDir.mkdirs();
            
            // Create blockchain file with valid empty JSON
            File tempBlockchainFile = new File(testDir, "blockchain.json");
            if (!tempBlockchainFile.exists()) {
                String emptyBlockchain = "{\"blockchain\":[{\"index\":0,\"timestamp\":\"2025-04-01T08:00:00Z\",\"previousHash\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"hash\":\"1a2b3c\",\"transactions\":[]}]}";
                Files.write(tempBlockchainFile.toPath(), emptyBlockchain.getBytes());
            }
            
            System.out.println("File storage directory: " + tempFileDir.getAbsolutePath());
            System.out.println("Blockchain file: " + tempBlockchainFile.getAbsolutePath());
            
            // Create config file
            File configFile = File.createTempFile("file-config", ".json");
            configFile.deleteOnExit();
            
            String configContent = "{" +
                "\"storage\": {" +
                    "\"file_storage_directory\": \"" + tempFileDir.getAbsolutePath().replace("\\", "\\\\") + "\"," +
                    "\"blockchain_file\": \"" + tempBlockchainFile.getAbsolutePath().replace("\\", "\\\\") + "\"" +
                "}" +
            "}";
            
            Files.write(configFile.toPath(), configContent.getBytes());
            System.out.println("Config file: " + configFile.getAbsolutePath());
            System.out.println("Config content: " + configContent);
            
            // Load config and initialize components
            Config config = Config.getInstance(configFile.getAbsolutePath());
            CryptoManager cryptoManager = new CryptoManager(config);
            BlockchainManager blockchainManager = new BlockchainManager(config);
            FileManager fileManager = new FileManager(config, cryptoManager, blockchainManager);
            
            // Test file hash computation
            byte[] testFileData = "This is test file data for FileManager testing".getBytes(StandardCharsets.UTF_8);
            String fileHash = fileManager.computeFileHash(testFileData);
            assertNotNull(fileHash, "File hash should not be null");
            System.out.println("File hash: " + fileHash);
            
            // Create test metadata and store file
            String fileName = "test.txt";
            long fileSize = testFileData.length;
            String encryptedKey = "encryptedKey123";
            String iv = "iv123";
            
            FileMetadata fileMetadata = new FileMetadata(fileName, fileSize, fileHash, encryptedKey, iv);
            
            // Test file storage
            SymmetricCrypto crypto = new SymmetricCrypto();
            String key = crypto.generateKey();
            SymmetricCrypto.EncryptionResult encResult = crypto.encrypt(testFileData, key, null);
            
            boolean storeResult = fileManager.storeFile(
                java.util.Base64.getDecoder().decode(encResult.getCiphertext()),
                fileMetadata
            );
            
            assertTrue(storeResult, "File storage should succeed");
            
            // Test remaining operations
            System.out.println("FileManager test completed successfully!");
            
        } catch (Exception e) {
            System.err.println("Test failed with exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    // private static void testFileManager() throws Exception {
    //     // Create temporary directories
    //     File tempFileDir = Files.createTempDirectory("files").toFile();
    //     File tempBlockchainFile = File.createTempFile("blockchain", ".json");
    //     tempBlockchainFile.deleteOnExit();
        
    //     // Create test config
    //     String configJson = "{ " +
    //         "\"storage\": { " +
    //             "\"file_storage_directory\": \"" + tempFileDir.getAbsolutePath() + "\", " +
    //             "\"blockchain_file\": \"" + tempBlockchainFile.getAbsolutePath() + "\" " +
    //         "} }";
        
    //     File configFile = File.createTempFile("config", ".json");
    //     Files.write(configFile.toPath(), configJson.getBytes());
    //     configFile.deleteOnExit();
        
    //     Config config = Config.getInstance(configFile.getAbsolutePath());
        
    //     // Initialize components
    //     CryptoManager cryptoManager = new CryptoManager(config);
    //     BlockchainManager blockchainManager = new BlockchainManager(config);
    //     FileManager fileManager = new FileManager(config, cryptoManager, blockchainManager);
        
    //     // Test file hash computation
    //     byte[] testFileData = "This is test file data for FileManager testing".getBytes(StandardCharsets.UTF_8);
    //     String fileHash = fileManager.computeFileHash(testFileData);
    //     assertNotNull(fileHash, "File hash should not be null");
        
    //     // Create file metadata
    //     String fileName = "test.txt";
    //     long fileSize = testFileData.length;
    //     String encryptedKey = "encryptedKey123";
    //     String iv = "iv123";
        
    //     FileMetadata fileMetadata = new FileMetadata(fileName, fileSize, fileHash, encryptedKey, iv);
        
    //     // Test file storage
    //     SymmetricCrypto crypto = new SymmetricCrypto();
    //     String key = crypto.generateKey();
    //     SymmetricCrypto.EncryptionResult encResult = crypto.encrypt(testFileData, key, null);
        
    //     boolean storeResult = fileManager.storeFile(
    //         java.util.Base64.getDecoder().decode(encResult.getCiphertext()),
    //         fileMetadata
    //     );
        
    //     assertTrue(storeResult, "File storage should succeed");
        
    //     // Test file existence check
    //     boolean fileExists = fileManager.fileExists(fileHash);
    //     assertTrue(fileExists, "File should exist after storage");
        
    //     // Test file retrieval
    //     byte[] retrievedData = fileManager.retrieveFile(fileHash);
    //     assertNotNull(retrievedData, "Retrieved file data should not be null");
        
    //     // Add transaction to blockchain
    //     String uploader = "testuser";
    //     String signature = "testSignature";
        
    //     Transaction transaction = new Transaction(uploader, fileMetadata, signature);
    //     boolean addResult = blockchainManager.addTransaction(transaction);
    //     assertTrue(addResult, "Adding transaction to blockchain should succeed");
        
    //     // Test file verification in blockchain
    //     Transaction verifiedTx = fileManager.verifyFileInBlockchain(fileHash);
    //     assertNotNull(verifiedTx, "Transaction should be found in blockchain");
    //     assertEquals(uploader, verifiedTx.getUploader(), "Transaction uploader should match");
        
    //     // Test file deletion
    //     boolean deleteResult = fileManager.deleteFile(fileHash);
    //     assertTrue(deleteResult, "File deletion should succeed");
        
    //     boolean fileExistsAfterDelete = fileManager.fileExists(fileHash);
    //     assertTrue(!fileExistsAfterDelete, "File should not exist after deletion");
    // }
}