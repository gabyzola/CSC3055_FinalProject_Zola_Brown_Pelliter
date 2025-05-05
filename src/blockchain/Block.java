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

public class Block {
    private String previousHash;
    private String blockHash;
    private long timestamp;
    private List<Transaction> transactions;

    // Constructor to create a new block
    public Block(String previousHash, List<Transaction> transactions) throws Exception {
        this.previousHash = previousHash;
        this.timestamp = Instant.now().toEpochMilli();
        this.transactions = transactions;
        this.blockHash = calculateHash(); // Use SHA3-256 for post-quantum-safe hashing
    }

    // Calculate block hash using SHA3-256 for quantum-resistant security
    private String calculateHash() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        StringBuilder input = new StringBuilder(previousHash)
                .append(timestamp);
        for (Transaction tx : transactions) {
            input.append(tx.toJSON());
        }
        byte[] hashBytes = digest.digest(input.toString().getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hashBytes);
    }

    // Validate the block against the previous hash and recalculate the hash
    public boolean isValid(String expectedPreviousHash) throws Exception {
        if (!this.previousHash.equals(expectedPreviousHash)) {
            return false;
        }
        String recalculated = calculateHash();
        return recalculated.equals(this.blockHash);
    }

    // Serialize the block to a JSON string
    public String toJSON() {
        JSONObject obj = new JSONObject();
        obj.put("previousHash", previousHash);
        obj.put("blockHash", blockHash);
        obj.put("timestamp", timestamp);

        JSONArray txArray = new JSONArray();
        for (Transaction tx : transactions) {
            txArray.add(new JSONObject());
        }
        obj.put("transactions", txArray);
        return obj.toString(); // Pretty-print with indentation
    }

    // Deserialize a Block object from a JSON string
    public static Block fromJSON(String json) throws Exception {
        JSONObject obj = new JSONObject();
        String previousHash = obj.getString("previousHash");
        long timestamp;
        try {
            timestamp = ((Number) obj.get("timestamp")).longValue();
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }
        JSONArray txArray = obj.getArray("transactions");

        List<Transaction> txList = new ArrayList<>();
        for (int i = 0; i < txArray.size(); i++) {
            JSONObject txJson = txArray.getObject(i);
            txList.add(Transaction.fromJSON(txJson.toString()));
        }

        Block block = new Block(previousHash, txList);
        block.timestamp = timestamp;
        block.blockHash = obj.getString("blockHash"); // Override to match saved hash
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
        return transactions;
    }
}
