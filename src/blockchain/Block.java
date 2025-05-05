package blockchain;

import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Represents a block in the blockchain containing transactions
 */
public class Block {
    private String previousHash;
    private String blockHash;
    private long timestamp;
    private List<Transaction> transactions;

    /**
     * Constructor to create a new block
     * @param previousHash Hash of the previous block
     * @param transactions List of transactions in this block
     * @throws Exception If block creation fails
     */
    public Block(String previousHash, List<Transaction> transactions) throws Exception {
        this.previousHash = previousHash;
        this.timestamp = Instant.now().getEpochSecond();
        this.transactions = new ArrayList<>(transactions);
        this.blockHash = calculateHash();
    }

    /**
     * Private constructor for deserialization
     */
    private Block() {
        this.transactions = new ArrayList<>();
    }

    /**
     * Calculate block hash using SHA3-256
     * @return Hash of the block
     * @throws NoSuchAlgorithmException If hashing algorithm is not available
     */
    private String calculateHash() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        StringBuilder input = new StringBuilder()
                .append(previousHash)
                .append(timestamp);
        
        for (Transaction tx : transactions) {
            input.append(tx.getTransactionId());
        }
        
        byte[] hashBytes = digest.digest(input.toString().getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    /**
     * Validates this block
     * @param expectedPreviousHash Expected previous hash
     * @return true if valid
     * @throws Exception If validation fails
     */
    public boolean isValid(String expectedPreviousHash) throws Exception {
        if (!this.previousHash.equals(expectedPreviousHash)) {
            return false;
        }
        
        String recalculated = calculateHash();
        return recalculated.equals(this.blockHash);
    }

    /**
     * Converts block to JSONObject
     * @return JSON representation
     */
    public JSONObject toJSONObject() {
        JSONObject obj = new JSONObject();
        obj.put("previousHash", previousHash);
        obj.put("blockHash", blockHash);
        obj.put("timestamp", timestamp);

        JSONArray txArray = new JSONArray();
        for (Transaction tx : transactions) {
            txArray.add(tx.toJSONObject());
        }
        obj.put("transactions", txArray);
        return obj;
    }

    /**
     * Deserialize from JSON
     * @param jsonObj JSON object to deserialize
     * @return Block object
     * @throws Exception If deserialization fails
     */
    public static Block fromJSON(JSONObject jsonObj) throws Exception {
        Block block = new Block();
        
        block.previousHash = jsonObj.getString("previousHash");
        block.blockHash = jsonObj.getString("blockHash");
        
        try {
            Number timestamp = (Number) jsonObj.get("timestamp");
            block.timestamp = timestamp.longValue();
        } catch (Exception e) {
            throw new Exception("Invalid block timestamp: " + e.getMessage());
        }

        JSONArray txArray = jsonObj.getArray("transactions");
        if (txArray != null) {
            for (int i = 0; i < txArray.size(); i++) {
                JSONObject txJson = txArray.getObject(i);
                Transaction tx = Transaction.fromJSON(txJson);
                block.transactions.add(tx);
            }
        }

        return block;
    }

    // Getters
    public String getPreviousHash() {
        return previousHash;
    }

    public String getBlockHash() {
        return blockHash;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public List<Transaction> getTransactions() {
        return new ArrayList<>(transactions);
    }
}