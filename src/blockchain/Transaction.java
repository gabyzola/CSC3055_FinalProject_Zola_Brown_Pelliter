package blockchain;

import merrimackutil.json.types.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;

public class Transaction {

    private String transactionId;
    private String uploaderId;
    private String fileHash;
    private long timestamp;
    private String signature; // base64-encoded signature of fileHash + timestamp + uploaderId

    // Constructor
    public Transaction(String uploaderId, String fileHash, String signature) throws Exception {
        this.uploaderId = uploaderId;
        this.fileHash = fileHash;
        this.timestamp = Instant.now().toEpochMilli();
        this.signature = signature;
        this.transactionId = computeTransactionId();
    }

    // Computes transaction ID as SHA3-256 hash of uploaderId + fileHash + timestamp
    private String computeTransactionId() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA3-256");
        String input = uploaderId + fileHash + timestamp;
        byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hash);
    }

    // Serialize to JSON
    public JSONObject toJSON() {
        JSONObject obj = new JSONObject();
        obj.put("transactionId", transactionId);
        obj.put("uploaderId", uploaderId);
        obj.put("fileHash", fileHash);
        obj.put("timestamp", timestamp);
        obj.put("signature", signature);
        return obj;
    }

    // Deserialize from JSON
    public static Transaction fromJSON(String json) throws Exception {
        JSONObject obj = new JSONObject();

        String uploaderId = obj.getString("uploaderId");
        String fileHash = obj.getString("fileHash");
        String signature = obj.getString("signature");
        long timestamp = ((Number) obj.get("timestamp")).longValue();
        String transactionId = obj.getString("transactionId");

        Transaction tx = new Transaction(uploaderId, fileHash, signature);
        tx.timestamp = timestamp;
        tx.transactionId = transactionId;

        return tx;
    }

    // Getters
    public String getTransactionId() {
        return transactionId;
    }

    public String getUploaderId() {
        return uploaderId;
    }

    public String getFileHash() {
        return fileHash;
    }

    public long getTimestamp() {
        return timestamp;
    }

    public String getSignature() {
        return signature;
    }

    // (Optional) validate the transaction’s integrity
    public boolean isValid() throws NoSuchAlgorithmException {
        return computeTransactionId().equals(transactionId);
    }
}
