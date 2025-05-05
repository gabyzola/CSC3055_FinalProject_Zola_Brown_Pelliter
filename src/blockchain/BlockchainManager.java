package blockchain;

import common.Config;
import common.Constants;
import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * BlockchainManager maintains the blockchain ledger of file transactions.
 * It supports transaction validation, block creation, and querying operations.
 */
public class BlockchainManager {
    // In-memory blockchain ledger
    private final List<Block> blockchain;
    
    // Pending transactions waiting to be added to a block
    private final List<Transaction> pendingTransactions;
    
    // File path for saving/loading the blockchain from disk
    private final String blockchainFile;
    
    // Maximum transactions per block
    private final int maxBlockSize;
    
    // Cache for faster lookups
    private final Map<String, Transaction> fileTransactionCache;
    
    /**
     * Constructor that initializes blockchain from configuration
     * @param config The system configuration
     * @throws IOException If blockchain file cannot be read
     */
    public BlockchainManager(Config config) throws IOException {
        this.blockchainFile = config.getString("storage.blockchain_file", Constants.BLOCKCHAIN_FILE);
        this.maxBlockSize = config.getInt("blockchain.block_size_limit", Constants.BLOCKCHAIN_MAX_BLOCK_SIZE);
        this.blockchain = new ArrayList<>();
        this.pendingTransactions = new ArrayList<>();
        this.fileTransactionCache = new HashMap<>();
        
        loadBlockchain();
        System.out.println("BlockchainManager: Initialized with " + blockchain.size() + " blocks");
    }
    
    /**
     * Loads blockchain from file or creates genesis block if not exists
     * @throws IOException If file operations fail
     */
    private void loadBlockchain() throws IOException {
        File file = new File(blockchainFile);
        
        // Create parent directories if they don't exist
        file.getParentFile().mkdirs();
        
        if (!file.exists() || file.length() == 0) {
            // Initialize with genesis block
            System.out.println("BlockchainManager: Creating genesis block");
            createGenesisBlock();
            saveBlockchain();
            return;
        }
        
        try {
            String json = Files.readString(file.toPath());
            JSONObject root = JsonIO.readObject(json);
            JSONArray blocksArray = root.getArray("blocks");
            
            if (blocksArray == null || blocksArray.size() == 0) {
                createGenesisBlock();
                return;
            }
            
            blockchain.clear();
            String previousHash = Constants.GENESIS_BLOCK_HASH;
            
            for (int i = 0; i < blocksArray.size(); i++) {
                JSONObject blockJson = blocksArray.getObject(i);
                Block block = Block.fromJSON(blockJson);
                
                // Validate block linkage
                if (!block.getPreviousHash().equals(previousHash)) {
                    System.err.println("BlockchainManager: Blockchain corrupted - invalid block linkage at index " + i);
                    throw new IOException("Blockchain integrity check failed");
                }
                
                blockchain.add(block);
                previousHash = block.getBlockHash();
                
                // Cache file transactions for faster lookup
                for (Transaction tx : block.getTransactions()) {
                    if (tx.getFileMetadata() != null) {
                        fileTransactionCache.put(tx.getFileMetadata().getFileHash(), tx);
                    }
                }
            }
            
            System.out.println("BlockchainManager: Loaded " + blockchain.size() + " blocks from " + blockchainFile);
            
        } catch (Exception e) {
            System.err.println("BlockchainManager: Error loading blockchain: " + e.getMessage());
            e.printStackTrace();
            
            // If loading fails, create a new blockchain
            blockchain.clear();
            createGenesisBlock();
            saveBlockchain();
        }
    }
    
    /**
     * Creates the genesis block for a new blockchain
     */
    private void createGenesisBlock() {
        try {
            blockchain.clear();
            fileTransactionCache.clear();
            
            List<Transaction> emptyList = new ArrayList<>();
            Block genesisBlock = new Block(Constants.GENESIS_BLOCK_HASH, emptyList);
            blockchain.add(genesisBlock);
            
        } catch (Exception e) {
            System.err.println("BlockchainManager: Failed to create genesis block: " + e.getMessage());
        }
    }
    
    /**
     * Saves the current blockchain to file
     * @throws IOException If file operations fail
     */
    private void saveBlockchain() throws IOException {
        JSONObject root = new JSONObject();
        JSONArray blocksArray = new JSONArray();
        
        for (Block block : blockchain) {
            JSONObject blockJson = block.toJSONObject();
            blocksArray.add(blockJson);
        }
        
        root.put("blocks", blocksArray);
        
        // Write atomically
        File tempFile = new File(blockchainFile + ".tmp");
        try (FileWriter writer = new FileWriter(tempFile)) {
            writer.write(root.toJSON());
        }
        
        File destFile = new File(blockchainFile);
        if (!tempFile.renameTo(destFile)) {
            Files.copy(tempFile.toPath(), destFile.toPath());
            tempFile.delete();
        }
    }
    
    /**
     * Adds a transaction to the blockchain
     * @param transaction The transaction to add
     * @return true if successful
     * @throws IOException If blockchain cannot be saved
     */
    public synchronized boolean addTransaction(Transaction transaction) throws IOException {
        if (transaction == null || transaction.getFileMetadata() == null) {
            return false;
        }
        
        // Validate the transaction
        try {
            if (!transaction.isValid()) {
                System.err.println("BlockchainManager: Invalid transaction");
                return false;
            }
        } catch (Exception e) {
            System.err.println("BlockchainManager: Error validating transaction: " + e.getMessage());
            return false;
        }
        
        // Add to pending transactions
        pendingTransactions.add(transaction);
        
        // If we have enough transactions, create a new block
        if (pendingTransactions.size() >= maxBlockSize) {
            return createNewBlock();
        }
        
        return true;
    }
    
    /**
     * Creates a new block with pending transactions
     * @return true if successful
     * @throws IOException If blockchain cannot be saved
     */
    public synchronized boolean createNewBlock() throws IOException {
        if (pendingTransactions.isEmpty()) {
            return true;
        }
        
        try {
            // Get the last block's hash
            String lastHash = blockchain.isEmpty() ? 
                Constants.GENESIS_BLOCK_HASH : 
                blockchain.get(blockchain.size() - 1).getBlockHash();
            
            // Create a new block with current transactions
            List<Transaction> blockTransactions = new ArrayList<>(pendingTransactions);
            Block newBlock = new Block(lastHash, blockTransactions);
            
            // Add to blockchain
            blockchain.add(newBlock);
            
            // Update cache
            for (Transaction tx : blockTransactions) {
                if (tx.getFileMetadata() != null) {
                    fileTransactionCache.put(tx.getFileMetadata().getFileHash(), tx);
                }
            }
            
            // Clear pending transactions
            pendingTransactions.clear();
            
            // Save to disk
            saveBlockchain();
            
            System.out.println("BlockchainManager: Added new block " + newBlock.getBlockHash() + 
                              " with " + blockTransactions.size() + " transactions");
            
            return true;
        } catch (Exception e) {
            System.err.println("BlockchainManager: Error creating new block: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    /**
     * Checks if a file exists in the blockchain
     * @param fileHash The file hash to check
     * @return true if the file exists
     */
    public boolean fileExists(String fileHash) {
        return fileTransactionCache.containsKey(fileHash);
    }
    
    /**
     * Finds the latest transaction for a file
     * @param fileHash The file hash to search for
     * @return The latest transaction or null if not found
     */
    public Transaction findLatestFileTransaction(String fileHash) {
        return fileTransactionCache.get(fileHash);
    }
    
    /**
     * Gets all file transactions
     * @return List of all file transactions
     */
    public List<Transaction> getAllFileTransactions() {
        return new ArrayList<>(fileTransactionCache.values());
    }
    
    /**
     * Gets all blocks in the blockchain
     * @return List of all blocks
     */
    public List<Block> getAllBlocks() {
        return new ArrayList<>(blockchain);
    }
    
    /**
     * Gets a block by its hash
     * @param blockHash The block hash
     * @return The block or null if not found
     */
    public Block getBlockByHash(String blockHash) {
        for (Block block : blockchain) {
            if (block.getBlockHash().equals(blockHash)) {
                return block;
            }
        }
        return null;
    }
    
    /**
     * Gets a transaction by its hash
     * @param transactionHash The transaction hash
     * @return The transaction or null if not found
     */
    public Transaction getTransactionByHash(String transactionHash) {
        for (Block block : blockchain) {
            for (Transaction tx : block.getTransactions()) {
                if (tx.getTransactionId().equals(transactionHash)) {
                    return tx;
                }
            }
        }
        return null;
    }
    
    /**
     * Gets all transactions for a file
     * @param fileHash The file hash
     * @return List of transactions for the file
     */
    public List<Transaction> getFileTransactions(String fileHash) {
        List<Transaction> result = new ArrayList<>();
        for (Block block : blockchain) {
            for (Transaction tx : block.getTransactions()) {
                if (tx.getFileMetadata() != null && 
                    tx.getFileMetadata().getFileHash().equals(fileHash)) {
                    result.add(tx);
                }
            }
        }
        return result;
    }
    
    /**
     * Gets all transactions for a user
     * @param username The username
     * @return List of transactions for the user
     */
    public List<Transaction> getUserTransactions(String username) {
        List<Transaction> result = new ArrayList<>();
        for (Block block : blockchain) {
            for (Transaction tx : block.getTransactions()) {
                if (tx.getUploaderId().equals(username)) {
                    result.add(tx);
                }
            }
        }
        return result;
    }
}