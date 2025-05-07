package blockchain;

import java.io.InvalidObjectException;
import java.time.Instant;
import java.util.UUID;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

/**
 * Represents a transaction in the blockchain for file operations.
 */
public class Transaction implements JSONSerializable {
    private String id;
    private String timestamp;
    private String uploader;
    private FileMetadata fileMetadata;
    private String signature;
    
    /**
     * Creates a new transaction
     * 
     * @param uploader Username of the file uploader
     * @param fileMetadata Metadata of the file
     * @param signature Base64-encoded Dilithium signature
     */
    public Transaction(String uploader, FileMetadata fileMetadata, String signature) {
        this.id = UUID.randomUUID().toString();
        this.timestamp = Instant.now().toString();
        this.uploader = uploader;
        this.fileMetadata = fileMetadata;
        this.signature = signature;
    }
    
    /**
     * Creates a transaction from a JSON object
     * 
     * @param json JSONObject containing transaction data
     * @throws InvalidObjectException If JSON is invalid
     */
    public Transaction(JSONObject json) throws InvalidObjectException {
        deserialize(json);
    }
    
    /**
     * Get the transaction ID
     * 
     * @return Transaction ID
     */
    public String getId() {
        return id;
    }
    
    /**
     * Get the transaction timestamp
     * 
     * @return ISO-8601 timestamp
     */
    public String getTimestamp() {
        return timestamp;
    }
    
    /**
     * Get the uploader username
     * 
     * @return Username
     */
    public String getUploader() {
        return uploader;
    }
    
    /**
     * Get the file metadata
     * 
     * @return FileMetadata
     */
    public FileMetadata getFileMetadata() {
        return fileMetadata;
    }
    
    /**
     * Get the transaction signature
     * 
     * @return Base64-encoded Dilithium signature
     */
    public String getSignature() {
        return signature;
    }
    
    /**
     * Get transaction content for signing (everything except signature)
     * 
     * @return JSON string for signing
     */
    public String getContentForSigning() {
        JSONObject json = new JSONObject();
        json.put("id", id);
        json.put("timestamp", timestamp);
        json.put("uploader", uploader);
        json.put("fileMetadata", fileMetadata.toJSONType());
        return json.toJSON();
    }

    @Override
    public JSONType toJSONType() {
        try {
            JSONObject json = new JSONObject();
            
            if (id == null) {
                id = UUID.randomUUID().toString();
                System.out.println("Warning: Transaction had null id, generating new one");
            }
            json.put("id", id);
            
            if (timestamp == null) {
                timestamp = Instant.now().toString();
                System.out.println("Warning: Transaction had null timestamp, using current time");
            }
            json.put("timestamp", timestamp);
            
            if (uploader == null) {
                System.err.println("Error: Transaction has null uploader");
                uploader = "unknown_user";  // Use a placeholder
            }
            json.put("uploader", uploader);
            
            if (fileMetadata == null) {
                System.err.println("Error: Transaction has null fileMetadata");
                throw new RuntimeException("Cannot create JSON for transaction with null fileMetadata");
            }
            
            try {
                JSONType metadataJson = fileMetadata.toJSONType();
                if (metadataJson != null) {
                    json.put("fileMetadata", metadataJson);
                } else {
                    System.err.println("Error: FileMetadata returned null JSON");
                    throw new RuntimeException("FileMetadata.toJSONType() returned null");
                }
            } catch (Exception e) {
                System.err.println("Error converting fileMetadata to JSON: " + e.getMessage());
                throw e;
            }
            
            if (signature == null) {
                System.out.println("Warning: Transaction had null signature");
                signature = "unsigned";  // Use a placeholder
            }
            json.put("signature", signature);
            
            return json;
        } catch (Exception e) {
            System.err.println("Error in Transaction.toJSONType: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Failed to convert Transaction to JSON: " + e.getMessage(), e);
        }
    }

    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!(obj instanceof JSONObject)) {
            throw new InvalidObjectException("Expected JSONObject for Transaction");
        }
        
        JSONObject json = (JSONObject) obj;
        
        // Validate required fields
        String[] requiredFields = {"id", "timestamp", "uploader", "fileMetadata", "signature"};
        for (String field : requiredFields) {
            if (!json.containsKey(field)) {
                throw new InvalidObjectException("Missing required field: " + field);
            }
        }
        
        this.id = json.getString("id");
        this.timestamp = json.getString("timestamp");
        this.uploader = json.getString("uploader");
        this.fileMetadata = new FileMetadata(json.getObject("fileMetadata"));
        this.signature = json.getString("signature");
    }
    
    @Override
    public String serialize() {
        return toJSONType().toJSON();
    }
}