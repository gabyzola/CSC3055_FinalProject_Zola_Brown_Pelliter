package blockchain;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InvalidObjectException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;

import common.Config;
import common.Constants;

/**
 * Manages the blockchain for file transactions.
 */
public class BlockchainManager {
    private List<Block> blockchain;
    private final ReadWriteLock lock = new ReentrantReadWriteLock();
    private String blockchainFilePath;
    
    /**
     * Create a new blockchain manager
     * 
     * @param config System configuration
     * @throws Exception If blockchain cannot be loaded or created
     */
    public BlockchainManager(Config config) throws Exception {
        this.blockchainFilePath = config.getString("storage.blockchain_file", "blockchain.json");
        loadBlockchain();
    }
    
    /**
     * Load the blockchain from disk or create a new one
     * 
     * @throws Exception If blockchain cannot be loaded or created
     */
    private void loadBlockchain() throws Exception {
        lock.writeLock().lock();
        try {
            File blockchainFile = new File(blockchainFilePath);
            if (blockchainFile.exists()) {
                // Load existing blockchain
                String jsonContent = new String(Files.readAllBytes(Paths.get(blockchainFilePath)));
                JSONObject json = JsonIO.readObject(jsonContent);
                
                blockchain = new ArrayList<>();
                JSONArray blocksArray = json.getArray("blockchain");
                
                // FIX: Check if blocksArray is null
                if (blocksArray == null) {
                    // Create new blockchain with genesis block
                    blockchain.add(Block.createGenesisBlock());
                    saveBlockchain();
                    return;
                }
                
                for (int i = 0; i < blocksArray.size(); i++) {
                    blockchain.add(new Block(blocksArray.getObject(i)));
                }
                
                // Validate blockchain integrity
                if (!isChainValid()) {
                    throw new InvalidObjectException("Blockchain integrity check failed");
                }
            } else {
                // Create new blockchain with genesis block
                blockchain = new ArrayList<>();
                blockchain.add(Block.createGenesisBlock());
                saveBlockchain();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Save the blockchain to disk
     * 
     * @throws IOException If blockchain cannot be saved
     */
    private void saveBlockchain() throws IOException {
        lock.readLock().lock();
        try {
            // Create parent directories if they don't exist
            File file = new File(blockchainFilePath);
            if (file.getParentFile() != null) {
                file.getParentFile().mkdirs();
            } else {
                System.err.println("Warning: No parent directory for blockchain file: " + blockchainFilePath);
            }
            
            JSONObject json = new JSONObject();
            JSONArray blocksArray = new JSONArray();
            
            for (Block block : blockchain) {
                try {
                    JSONObject blockJson = (JSONObject) block.toJSONType();
                    if (blockJson != null) {
                        blocksArray.add(blockJson);
                    } else {
                        System.err.println("Warning: Block returned null JSON: " + block.getIndex());
                    }
                } catch (Exception e) {
                    System.err.println("Error converting block to JSON: " + e.getMessage());
                }
            }
            
            json.put("blockchain", blocksArray);
            
            System.out.println("Saving blockchain with " + blocksArray.size() + " blocks to " + blockchainFilePath);
            
            try (FileWriter writer = new FileWriter(blockchainFilePath)) {
                writer.write(json.toJSON());
            } catch (IOException e) {
                System.err.println("Error writing blockchain to file: " + e.getMessage());
                throw e;
            }
        } catch (Exception e) {
            System.err.println("Error in saveBlockchain: " + e.getMessage());
            e.printStackTrace();
            throw new IOException("Failed to save blockchain: " + e.getMessage(), e);
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Add a new transaction to the blockchain
     * 
     * @param transaction The transaction to add
     * @return true if successful
     * @throws Exception If transaction cannot be added
     */
    public boolean addTransaction(Transaction transaction) throws Exception {
        if (transaction == null) {
            System.err.println("Error: Cannot add null transaction to blockchain");
            return false;
        }
        
        if (transaction.getFileMetadata() == null) {
            System.err.println("Error: Transaction has null file metadata");
            return false;
        }
        
        if (transaction.getUploader() == null) {
            System.err.println("Error: Transaction has null uploader");
            return false;
        }
        
        lock.writeLock().lock();
        try {
            System.out.println("Adding transaction to blockchain for file: " + 
                               transaction.getFileMetadata().getFileName() + 
                               " by user: " + transaction.getUploader());
            
            // Get the last block
            Block lastBlock = blockchain.get(blockchain.size() - 1);
            
            // Check if the last block has space
            if (lastBlock.getTransactions().size() < Constants.BLOCK_SIZE_LIMIT) {
                // Add to existing block
                lastBlock.addTransaction(transaction);
                System.out.println("Added transaction to existing block: " + lastBlock.getIndex());
            } else {
                // Create a new block
                List<Transaction> transactions = new ArrayList<>();
                transactions.add(transaction);
                Block newBlock = new Block(lastBlock.getIndex() + 1, lastBlock.getHash(), transactions);
                blockchain.add(newBlock);
                System.out.println("Created new block: " + newBlock.getIndex() + " for transaction");
            }
            
            // Save the updated blockchain
            saveBlockchain();
            return true;
        } catch (Exception e) {
            System.err.println("Error adding transaction to blockchain: " + e.getMessage());
            e.printStackTrace();
            throw e;
        } finally {
            lock.writeLock().unlock();
        }
    }
    
    /**
     * Verify if a file exists in the blockchain
     * 
     * @param fileHash The hash of the file to verify
     * @return The transaction containing the file, or null if not found
     */
    public Transaction verifyFile(String fileHash) {
        lock.readLock().lock();
        try {
            for (Block block : blockchain) {
                for (Transaction tx : block.getTransactions()) {
                    if (tx.getFileMetadata().getFileHash().equals(fileHash)) {
                        return tx;
                    }
                }
            }
            return null;
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Get all transactions for a specific user
     * 
     * @param username The username to filter by
     * @return List of transactions for the user
     */
    public List<Transaction> getUserTransactions(String username) {
        lock.readLock().lock();
        try {
            List<Transaction> userTransactions = new ArrayList<>();
            
            for (Block block : blockchain) {
                for (Transaction tx : block.getTransactions()) {
                    if (tx.getUploader().equals(username)) {
                        userTransactions.add(tx);
                    }
                }
            }
            
            return userTransactions;
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Get all transactions in the blockchain
     * 
     * @return List of all transactions
     */
    public List<Transaction> getAllTransactions() {
        lock.readLock().lock();
        try {
            List<Transaction> allTransactions = new ArrayList<>();
            
            for (Block block : blockchain) {
                allTransactions.addAll(block.getTransactions());
            }
            
            return allTransactions;
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Get the entire blockchain
     * 
     * @return List of all blocks
     */
    public List<Block> getBlockchain() {
        lock.readLock().lock();
        try {
            return new ArrayList<>(blockchain);
        } finally {
            lock.readLock().unlock();
        }
    }
    
    /**
     * Check if the blockchain is valid (hash integrity)
     * 
     * @return true if the chain is valid
     */
    public boolean isChainValid() {
        lock.readLock().lock();
        try {
            for (int i = 1; i < blockchain.size(); i++) {
                Block currentBlock = blockchain.get(i);
                Block previousBlock = blockchain.get(i - 1);
                
                // Check hash integrity
                if (!currentBlock.isValid()) {
                    return false;
                }
                
                // Check hash linkage
                if (!currentBlock.getPreviousHash().equals(previousBlock.getHash())) {
                    return false;
                }
            }
            
            return true;
        } finally {
            lock.readLock().unlock();
        }
    }
}