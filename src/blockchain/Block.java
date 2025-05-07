package blockchain;

import java.io.InvalidObjectException;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

import common.Constants;

/**
 * Represents a block in the blockchain containing multiple transactions.
 */
public class Block implements JSONSerializable {
    private int index;
    private String timestamp;
    private String previousHash;
    private String hash;
    private List<Transaction> transactions;
    
    /**
     * Creates a new block
     * 
     * @param index The block index (0 for genesis)
     * @param previousHash Hash of the previous block
     * @param transactions List of transactions in this block
     */
    public Block(int index, String previousHash, List<Transaction> transactions) {
        this.index = index;
        this.timestamp = Instant.now().toString();
        this.previousHash = previousHash;
        this.transactions = transactions;
        this.hash = calculateHash();
    }
    
    /**
     * Creates a new genesis block
     * 
     * @return The genesis block
     */
    public static Block createGenesisBlock() {
        return new Block(0, Constants.GENESIS_BLOCK_HASH, new ArrayList<>());
    }
    
    /**
     * Creates a block from a JSON object
     * 
     * @param json JSONObject containing block data
     * @throws InvalidObjectException If JSON is invalid
     */
    public Block(JSONObject json) throws InvalidObjectException {
        deserialize(json);
    }
    
    /**
     * Get the block index
     * 
     * @return Block index
     */
    public int getIndex() {
        return index;
    }
    
    /**
     * Get the block timestamp
     * 
     * @return ISO-8601 timestamp
     */
    public String getTimestamp() {
        return timestamp;
    }
    
    /**
     * Get the previous block hash
     * 
     * @return Base64-encoded hash
     */
    public String getPreviousHash() {
        return previousHash;
    }
    
    /**
     * Get the block hash
     * 
     * @return Base64-encoded hash
     */
    public String getHash() {
        return hash;
    }
    
    /**
     * Get the transactions in this block
     * 
     * @return List of transactions
     */
    public List<Transaction> getTransactions() {
        return transactions;
    }
    
    /**
     * Add a transaction to this block
     * 
     * @param transaction The transaction to add
     * @return true if successful, false if block is full
     */
    public boolean addTransaction(Transaction transaction) {
        if (transactions.size() >= Constants.BLOCK_SIZE_LIMIT) {
            return false;
        }
        
        transactions.add(transaction);
        this.hash = calculateHash();
        return true;
    }
    
    /**
     * Calculate the hash of this block
     * 
     * @return Base64-encoded SHA3-512 hash
     */
    public String calculateHash() {
        try {
            MessageDigest digest = MessageDigest.getInstance(Constants.HASH_ALGORITHM);
            
            // Include all block data in hash
            String data = index + timestamp + previousHash + getTransactionsString();
            byte[] hashBytes = digest.digest(data.getBytes());
            
            return Base64.getEncoder().encodeToString(hashBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error calculating block hash", e);
        }
    }
    
    /**
     * Validate the block's hash
     * 
     * @return true if the hash is valid
     */
    public boolean isValid() {
        return hash.equals(calculateHash());
    }
    
    /**
     * Get transactions as a string for hashing
     * 
     * @return String representation of transactions
     */
    private String getTransactionsString() {
        StringBuilder sb = new StringBuilder();
        for (Transaction tx : transactions) {
            sb.append(tx.serialize());
        }
        return sb.toString();
    }

    @Override
    public JSONType toJSONType() {
        try {
            JSONObject json = new JSONObject();
            json.put("index", index);
            
            if (timestamp == null) {
                timestamp = Instant.now().toString();  // Use current time if null
                System.out.println("Warning: Block had null timestamp, using current time");
            }
            json.put("timestamp", timestamp);
            
            if (previousHash == null) {
                previousHash = Constants.GENESIS_BLOCK_HASH;  // Use genesis hash if null
                System.out.println("Warning: Block had null previousHash, using genesis hash");
            }
            json.put("previousHash", previousHash);
            
            if (hash == null) {
                hash = calculateHash();  // Recalculate if null
                System.out.println("Warning: Block had null hash, recalculating");
            }
            json.put("hash", hash);
            
            JSONArray txArray = new JSONArray();
            if (transactions != null) {
                for (Transaction tx : transactions) {
                    if (tx != null) {
                        try {
                            JSONType txJson = tx.toJSONType();
                            if (txJson != null) {
                                txArray.add(txJson);
                            } else {
                                System.err.println("Warning: Transaction returned null JSON");
                            }
                        } catch (Exception e) {
                            System.err.println("Error converting transaction to JSON: " + e.getMessage());
                        }
                    } else {
                        System.err.println("Warning: Null transaction in block");
                    }
                }
            } else {
                transactions = new ArrayList<>();  // Initialize if null
                System.err.println("Warning: Block had null transactions list");
            }
            json.put("transactions", txArray);
            
            return json;
        } catch (Exception e) {
            System.err.println("Error in Block.toJSONType: " + e.getMessage());
            e.printStackTrace();
            
            // Return a minimal valid block JSON as fallback
            JSONObject fallback = new JSONObject();
            fallback.put("index", index);
            fallback.put("timestamp", Instant.now().toString());
            fallback.put("previousHash", Constants.GENESIS_BLOCK_HASH);
            fallback.put("hash", "INVALID_HASH");
            fallback.put("transactions", new JSONArray());
            return fallback;
        }
    }

    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!(obj instanceof JSONObject)) {
            throw new InvalidObjectException("Expected JSONObject for Block");
        }
        
        JSONObject json = (JSONObject) obj;
        
        // Validate required fields
        String[] requiredFields = {"index", "timestamp", "previousHash", "hash", "transactions"};
        for (String field : requiredFields) {
            if (!json.containsKey(field)) {
                throw new InvalidObjectException("Missing required field: " + field);
            }
        }
        
        // Handle index more robustly
        Object indexObj = json.get("index");
        if (indexObj == null) {
            throw new InvalidObjectException("index is null");
        }
        
        if (indexObj instanceof Number) {
            this.index = ((Number) indexObj).intValue();
        } else {
            try {
                this.index = Integer.parseInt(indexObj.toString());
            } catch (NumberFormatException e) {
                throw new InvalidObjectException("Invalid index format: " + indexObj);
            }
        }
        
        this.timestamp = json.getString("timestamp");
        this.previousHash = json.getString("previousHash");
        this.hash = json.getString("hash");
        
        this.transactions = new ArrayList<>();
        JSONArray txArray = json.getArray("transactions");
        for (int i = 0; i < txArray.size(); i++) {
            this.transactions.add(new Transaction(txArray.getObject(i)));
        }
    }
    
    @Override
    public String serialize() {
        return toJSONType().toJSON();
    }
}