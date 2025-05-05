package blockchain;

import merrimackutil.json.types.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

/**
 * Represents a transaction in the blockchain
 */
public class Transaction {
    private String transactionId;
    private String uploaderId;
    private String type;
    private FileMetadata fileMetadata;
    private long timestamp;
    private byte[] signature;

    /**
     * Constructor for a transaction
     * @param uploaderId ID of the uploader
     * @param type Type of transaction (UPLOAD, SHARE, etc.)
     * @param fileMetadata Metadata of the file
     * @param timestamp Timestamp of the transaction
     * @throws NoSuchAlgorithmException If hash algorithm not available
     */
    public Transaction(String uploaderId, String type, FileMetadata fileMetadata, long timestamp) 
            throws NoSuchAlgorithmException {
        this.uploaderId = uploaderId;
        this.type = type;
        this.fileMetadata = fileMetadata;
        this.timestamp = timestamp;
        this.transactionId = computeTransactionId();
    }

    /**
     * Private constructor for deserialization
     */
    private Transaction() {
    }

    /**
     * Computes transaction ID
     * @return Transaction ID
     * @throws NoSuchAlgorithmException If hash algorithm not available
     */
    private String computeTransactionId() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        StringBuilder input = new StringBuilder()
                .append(uploaderId)
                .append(type)
                .append(timestamp);
        
        if (fileMetadata != null) {
            input.append(fileMetadata.getFileHash());
        }
        
        byte[] hash = digest.digest(input.toString().getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * Set the digital signature for the transaction
     * @param signature The signature
     */
    public void setSignature(byte[] signature) {
        this.signature = signature.clone();
    }

    /**
     * Convert to JSONObject
     * @return JSON representation
     */
    public JSONObject toJSONObject() {
        JSONObject obj = new JSONObject();
        obj.put("transactionId", transactionId);
        obj.put("uploaderId", uploaderId);
        obj.put("type", type);
        obj.put("timestamp", timestamp);
        
        if (signature != null) {
            obj.put("signature", Base64.getEncoder().encodeToString(signature));
        }
        
        if (fileMetadata != null) {
            obj.put("fileMetadata", fileMetadata.toJSONObject());
        }
        
        return obj;
    }

    /**
     * Get data to sign
     * @return Data to be signed
     */
    public byte[] getDataToSign() {
        StringBuilder builder = new StringBuilder()
                .append(transactionId)
                .append(uploaderId)
                .append(type)
                .append(timestamp);
        
        if (fileMetadata != null) {
            builder.append(fileMetadata.getFileHash());
        }
        
        return builder.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Deserialize from JSON
     * @param jsonObj JSON object to deserialize
     * @return Transaction object
     * @throws Exception If deserialization fails
     */
    public static Transaction fromJSON(JSONObject jsonObj) throws Exception {
        Transaction tx = new Transaction();
        
        tx.transactionId = jsonObj.getString("transactionId");
        tx.uploaderId = jsonObj.getString("uploaderId");
        tx.type = jsonObj.getString("type");
        
        Number timestamp = (Number) jsonObj.get("timestamp");
        tx.timestamp = timestamp.longValue();
        
        String signatureStr = jsonObj.getString("signature");
        if (signatureStr != null) {
            tx.signature = Base64.getDecoder().decode(signatureStr);
        }
        
        JSONObject metadataObj = jsonObj.getObject("fileMetadata");
        if (metadataObj != null) {
            tx.fileMetadata = FileMetadata.fromJSON(metadataObj);
        }
        
        return tx;
    }

    /**
     * Validates the transaction
     * @return true if valid
     * @throws NoSuchAlgorithmException If hash algorithm not available
     */
    public boolean isValid() throws NoSuchAlgorithmException {
        // Check transaction ID
        String calculatedId = computeTransactionId();
        return calculatedId.equals(transactionId);
    }

    // Getters
    public String getTransactionId() {
        return transactionId;
    }

    public String getUploaderId() {
        return uploaderId;
    }

    public String getType() {
        return type;
    }

    public FileMetadata getFileMetadata() {
        return fileMetadata;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public byte[] getSignature() {
        return signature != null ? signature.clone() : null;
    }
}