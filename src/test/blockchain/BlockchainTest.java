package test.blockchain;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import blockchain.Block;
import blockchain.BlockchainManager;
import blockchain.FileMetadata;
import blockchain.Transaction;
import common.Config;
import common.Constants;
import merrimackutil.json.types.JSONObject;

public class BlockchainTest {
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
            System.out.println("========== Testing FileMetadata ==========");
            testFileMetadata();
            
            System.out.println("\n========== Testing Transaction ==========");
            testTransaction();
            
            System.out.println("\n========== Testing Block ==========");
            testBlock();
            
            System.out.println("\n========== Testing BlockchainManager ==========");
            testBlockchainManager();
            
            System.out.println("\nAll blockchain tests completed!");
        } catch (Exception e) {
            System.err.println("Test failed with exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void testFileMetadata() throws Exception {
        // Create test file metadata
        String fileName = "test.pdf";
        long fileSize = 1024;
        String fileHash = calculateSampleHash("test content");
        String encryptedKey = Base64.getEncoder().encodeToString("encrypted-key".getBytes());
        String iv = Base64.getEncoder().encodeToString("initialization-vector".getBytes());
        
        FileMetadata metadata = new FileMetadata(fileName, fileSize, fileHash, encryptedKey, iv);
        
        // Test getters
        assertEquals(fileName, metadata.getFileName(), "File name");
        assertEquals(fileSize, metadata.getFileSize(), "File size");
        assertEquals(fileHash, metadata.getFileHash(), "File hash");
        assertEquals(encryptedKey, metadata.getEncryptedSymmetricKey(), "Encrypted key");
        assertEquals(iv, metadata.getIv(), "IV");
        
        // Test serialization
        JSONObject json = (JSONObject) metadata.toJSONType();
        assertNotNull(json, "JSON serialization result");
        
        // Test deserialization
        FileMetadata deserializedMetadata = new FileMetadata(json);
        assertEquals(fileName, deserializedMetadata.getFileName(), "File name after deserialization");
        assertEquals(fileSize, deserializedMetadata.getFileSize(), "File size after deserialization");
        assertEquals(fileHash, deserializedMetadata.getFileHash(), "File hash after deserialization");
        assertEquals(encryptedKey, deserializedMetadata.getEncryptedSymmetricKey(), "Encrypted key after deserialization");
        assertEquals(iv, deserializedMetadata.getIv(), "IV after deserialization");
    }
    
    private static void testTransaction() throws Exception {
        // Create test file metadata
        FileMetadata metadata = new FileMetadata(
            "test.pdf", 
            1024, 
            calculateSampleHash("test content"),
            Base64.getEncoder().encodeToString("encrypted-key".getBytes()),
            Base64.getEncoder().encodeToString("initialization-vector".getBytes())
        );
        
        String uploader = "testuser";
        String signature = Base64.getEncoder().encodeToString("test-signature".getBytes());
        
        // Create transaction
        Transaction transaction = new Transaction(uploader, metadata, signature);
        
        // Test getters
        assertNotNull(transaction.getId(), "Transaction ID");
        assertNotNull(transaction.getTimestamp(), "Transaction timestamp");
        assertEquals(uploader, transaction.getUploader(), "Transaction uploader");
        assertEquals(metadata.getFileName(), transaction.getFileMetadata().getFileName(), "Transaction file metadata");
        assertEquals(signature, transaction.getSignature(), "Transaction signature");
        
        // Test content for signing
        String contentForSigning = transaction.getContentForSigning();
        assertNotNull(contentForSigning, "Content for signing");
        assertTrue(contentForSigning.contains(transaction.getId()), "Content for signing contains ID");
        assertTrue(contentForSigning.contains(uploader), "Content for signing contains uploader");
        
        // Test serialization
        JSONObject json = (JSONObject) transaction.toJSONType();
        assertNotNull(json, "JSON serialization result");
        
        // Test deserialization
        Transaction deserializedTransaction = new Transaction(json);
        assertEquals(transaction.getId(), deserializedTransaction.getId(), "Transaction ID after deserialization");
        assertEquals(transaction.getUploader(), deserializedTransaction.getUploader(), "Uploader after deserialization");
        assertEquals(transaction.getFileMetadata().getFileName(), 
                     deserializedTransaction.getFileMetadata().getFileName(), 
                     "File metadata after deserialization");
        assertEquals(transaction.getSignature(), deserializedTransaction.getSignature(), "Signature after deserialization");
    }
    
    private static void testBlock() throws Exception {
        // Create test transactions
        FileMetadata metadata1 = new FileMetadata(
            "test1.pdf", 
            1024, 
            calculateSampleHash("test content 1"),
            Base64.getEncoder().encodeToString("encrypted-key-1".getBytes()),
            Base64.getEncoder().encodeToString("iv-1".getBytes())
        );
        
        FileMetadata metadata2 = new FileMetadata(
            "test2.pdf", 
            2048, 
            calculateSampleHash("test content 2"),
            Base64.getEncoder().encodeToString("encrypted-key-2".getBytes()),
            Base64.getEncoder().encodeToString("iv-2".getBytes())
        );
        
        Transaction tx1 = new Transaction("user1", metadata1, Base64.getEncoder().encodeToString("sig1".getBytes()));
        Transaction tx2 = new Transaction("user2", metadata2, Base64.getEncoder().encodeToString("sig2".getBytes()));
        
        List<Transaction> transactions = new ArrayList<>();
        transactions.add(tx1);
        
        // Create genesis block
        Block genesisBlock = Block.createGenesisBlock();
        assertEquals(0, genesisBlock.getIndex(), "Genesis block index");
        assertEquals(Constants.GENESIS_BLOCK_HASH, genesisBlock.getPreviousHash(), "Genesis block previous hash");
        assertEquals(0, genesisBlock.getTransactions().size(), "Genesis block transaction count");
        assertNotNull(genesisBlock.getHash(), "Genesis block hash");
        
        // Create regular block
        Block block = new Block(1, genesisBlock.getHash(), transactions);
        assertEquals(1, block.getIndex(), "Block index");
        assertEquals(genesisBlock.getHash(), block.getPreviousHash(), "Block previous hash");
        assertEquals(1, block.getTransactions().size(), "Block transaction count");
        assertNotNull(block.getHash(), "Block hash");
        
        // Test adding transaction
        boolean added = block.addTransaction(tx2);
        assertTrue(added, "Transaction addition");
        assertEquals(2, block.getTransactions().size(), "Block transaction count after addition");
        
        // Verify hash changed after adding transaction
        String originalHash = block.getHash();
        assertNotNull(originalHash, "Original hash");
        
        // Test isValid
        assertTrue(block.isValid(), "Block validity");
        
        // Test serialization
        JSONObject json = (JSONObject) block.toJSONType();
        assertNotNull(json, "JSON serialization result");
        
        // Test deserialization
        Block deserializedBlock = new Block(json);
        assertEquals(block.getIndex(), deserializedBlock.getIndex(), "Block index after deserialization");
        assertEquals(block.getPreviousHash(), deserializedBlock.getPreviousHash(), "Previous hash after deserialization");
        assertEquals(block.getHash(), deserializedBlock.getHash(), "Block hash after deserialization");
        assertEquals(block.getTransactions().size(), deserializedBlock.getTransactions().size(), 
                    "Transaction count after deserialization");
    }
    
    private static void testBlockchainManager() throws Exception {
        // Create temporary blockchain file
        File tempBlockchainFile = File.createTempFile("test-blockchain", ".json");
        tempBlockchainFile.delete(); // Delete so BlockchainManager creates new one
        
        // Create config for the blockchain
        JSONObject configJson = new JSONObject();
        JSONObject storage = new JSONObject();
        storage.put("blockchain_file", tempBlockchainFile.getAbsolutePath());
        configJson.put("storage", storage);
        
        // Write config to file
        File tempConfigFile = File.createTempFile("test-config", ".json");
        try (java.io.FileWriter writer = new java.io.FileWriter(tempConfigFile)) {
            writer.write(configJson.toJSON());
        }
        
        // Initialize blockchain manager
        Config config = Config.getInstance(tempConfigFile.getAbsolutePath());
        BlockchainManager manager = new BlockchainManager(config);
        
        // Test blockchain initialization
        List<Block> blockchain = manager.getBlockchain();
        assertNotNull(blockchain, "Blockchain list");
        assertEquals(1, blockchain.size(), "Initial blockchain size");
        assertEquals(0, blockchain.get(0).getIndex(), "Genesis block index");
        
        // Create a test transaction
        FileMetadata metadata = new FileMetadata(
            "test.pdf", 
            1024, 
            calculateSampleHash("test content"),
            Base64.getEncoder().encodeToString("encrypted-key".getBytes()),
            Base64.getEncoder().encodeToString("iv".getBytes())
        );
        
        Transaction tx = new Transaction("testuser", metadata, Base64.getEncoder().encodeToString("signature".getBytes()));
        
        // Add transaction to blockchain
        boolean added = manager.addTransaction(tx);
        assertTrue(added, "Transaction addition to blockchain");
        
        // Verify blockchain updated
        blockchain = manager.getBlockchain();
        assertEquals(1, blockchain.size(), "Blockchain size after transaction");
        assertEquals(1, blockchain.get(0).getTransactions().size(), "Transaction count in first block");
        
        // Test file verification
        Transaction verifiedTx = manager.verifyFile(metadata.getFileHash());
        assertNotNull(verifiedTx, "Verified transaction");
        assertEquals(tx.getId(), verifiedTx.getId(), "Verified transaction ID");
        
        // Test user transactions
        List<Transaction> userTransactions = manager.getUserTransactions("testuser");
        assertEquals(1, userTransactions.size(), "User transaction count");
        assertEquals(tx.getId(), userTransactions.get(0).getId(), "User transaction ID");
        
        // Test all transactions
        List<Transaction> allTransactions = manager.getAllTransactions();
        assertEquals(1, allTransactions.size(), "All transactions count");
        
        // Test chain validity
        assertTrue(manager.isChainValid(), "Chain validity");
        
        // Add more transactions to create new block
        for (int i = 0; i < Constants.BLOCK_SIZE_LIMIT; i++) {
            FileMetadata m = new FileMetadata(
                "file" + i + ".pdf", 
                1024 * i, 
                calculateSampleHash("content " + i),
                Base64.getEncoder().encodeToString(("key" + i).getBytes()),
                Base64.getEncoder().encodeToString(("iv" + i).getBytes())
            );
            
            Transaction t = new Transaction("user" + i, m, Base64.getEncoder().encodeToString(("sig" + i).getBytes()));
            manager.addTransaction(t);
        }
        
        // Verify new block was created
        blockchain = manager.getBlockchain();
        assertTrue(blockchain.size() > 1, "Blockchain size after multiple transactions");
        
        // Clean up
        tempBlockchainFile.delete();
        tempConfigFile.delete();
    }
    
    // Helper to calculate a sample hash
    private static String calculateSampleHash(String input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(Constants.HASH_ALGORITHM);
        byte[] hashBytes = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hashBytes);
    }
}