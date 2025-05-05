package blockchain;

import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;

/**
 * BlockchainManager manages a list of blocks containing file transactions.
 * It supports blockchain validation, JSON-based persistence, and querying.
 */
public class BlockchainManager {
    // In-memory blockchain ledger
    private final List<Block> blockchain;

    // File path for saving/loading the blockchain to/from disk
    private final String persistenceFile;

    // Constructor initializes blockchain and sets the file for persistence
    public BlockchainManager(String persistenceFile) {
        this.persistenceFile = persistenceFile;
        this.blockchain = new ArrayList<>();
    }

    /**
     * Load the blockchain from a JSON file if it exists.
     * Validates each block's hash and linkage during load.
     */
    public void load() throws Exception {
        File file = new File(persistenceFile);
        if (!file.exists()) return;

        String json = Files.readString(file.toPath());
        JSONArray arr = new JSONArray();

        blockchain.clear();
        for (int i = 0; i < arr.size(); i++) {
            JSONObject blockJson = arr.getObject(i);
            Block block = Block.fromJSON(blockJson.toString());

            // Validate block linkage and hash integrity
            String expectedPrev = (blockchain.isEmpty()) ? "GENESIS" : blockchain.get(blockchain.size() - 1).getBlockHash();
            if (!validateBlock(block, expectedPrev)) {
                throw new Exception("Blockchain corrupted at block index " + i);
            }

            blockchain.add(block);
        }
    }

    /**
     * Save the current blockchain to a JSON file.
     */
    public void save() throws IOException {
        JSONArray arr = new JSONArray();
        for (Block block : blockchain) {
            arr.add(block.toJSON());
        }

        try (FileWriter fw = new FileWriter(persistenceFile)) {
            fw.write(arr.toString());
        }
    }

    /**
     * Add a new block to the blockchain after validating transactions and block integrity.
     * This represents the consensus mechanism (append-only).
     */
    public boolean addBlock(List<Transaction> transactions) throws Exception {
        // Ensure all transactions are valid
        for (Transaction tx : transactions) {
            if (!tx.isValid()) return false;
        }

        // Use last block’s hash or “GENESIS” if first block
        String previousHash = blockchain.isEmpty() ? "GENESIS" : blockchain.get(blockchain.size() - 1).getBlockHash();

        // Create and validate the new block
        Block newBlock = new Block(previousHash, transactions);
        if (!validateBlock(newBlock, previousHash)) return false;

        // Add to blockchain and persist to file
        blockchain.add(newBlock);
        save();
        return true;
    }

    /**
     * Validates a block by checking previous hash match and hash integrity.
     */
    private boolean validateBlock(Block block, String expectedPreviousHash) throws Exception {
        return block.isValid(expectedPreviousHash);
    }

    /**
     * Search for a transaction by file hash.
     * Returns the first match found or null.
     */
    public Transaction findTransactionByFileHash(String targetFileHash) {
        for (Block block : blockchain) {
            for (Transaction tx : block.getTransactions()) {
                FileMetadata meta = tx.getMetadata();
                if (meta.getFileHash().equals(targetFileHash)) {
                    return tx;
                }
            }
        }
        return null;
    }

    /**
     * Search for all transactions related to a specific user (uploader or allowed user).
     */
    public List<Transaction> findTransactionsByUser(String userId) {
        List<Transaction> results = new ArrayList<>();
        for (Block block : blockchain) {
            for (Transaction tx : block.getTransactions()) {
                FileMetadata meta = tx.getMetadata();
                if (meta.getUploaderId().equals(userId) || meta.getAllowedUsers().contains(userId)) {
                    results.add(tx);
                }
            }
        }
        return results;
    }

    /**
     * Check whether a user has permission to access a file based on its hash.
     */
    public boolean userHasAccess(String userId, String fileHash) {
        Transaction tx = findTransactionByFileHash(fileHash);
        if (tx == null) return false;

        FileMetadata meta = tx.getMetadata();
        return meta.getUploaderId().equals(userId) || meta.getAllowedUsers().contains(userId);
    }

    /**
     * Get the number of blocks in the blockchain.
     */
    public int getChainLength() {
        return blockchain.size();
    }

    /**
     * Get a read-only copy of the current blockchain.
     */
    public List<Block> getBlockchain() {
        return new ArrayList<>(blockchain); // Defensive copy
    }
}