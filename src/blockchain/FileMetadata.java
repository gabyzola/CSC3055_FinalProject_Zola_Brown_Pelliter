package blockchain;

import java.io.InvalidObjectException;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

/**
 * Represents metadata for a file stored in the blockchain.
 */
public class FileMetadata implements JSONSerializable {
    private String fileName;
    private long fileSize;
    private String fileHash;
    private String encryptedSymmetricKey;
    private String iv;
    
    /**
     * Creates a new file metadata instance
     * 
     * @param fileName The name of the file
     * @param fileSize The size of the file in bytes
     * @param fileHash SHA3-512 hash of the file content
     * @param encryptedSymmetricKey Base64-encoded encrypted AES key
     * @param iv Base64-encoded initialization vector for AES-GCM
     */
    public FileMetadata(String fileName, long fileSize, String fileHash, 
                        String encryptedSymmetricKey, String iv) {
        this.fileName = fileName;
        this.fileSize = fileSize;
        this.fileHash = fileHash;
        this.encryptedSymmetricKey = encryptedSymmetricKey;
        this.iv = iv;
    }
    
    /**
     * Creates file metadata from a JSON object
     * 
     * @param json JSONObject containing file metadata
     * @throws InvalidObjectException If JSON is invalid
     */
    public FileMetadata(JSONObject json) throws InvalidObjectException {
        deserialize(json);
    }
    
    /**
     * Get the file name
     * 
     * @return The file name
     */
    public String getFileName() {
        return fileName;
    }
    
    /**
     * Get the file size in bytes
     * 
     * @return The file size
     */
    public long getFileSize() {
        return fileSize;
    }
    
    /**
     * Get the file hash
     * 
     * @return Base64-encoded SHA3-512 hash
     */
    public String getFileHash() {
        return fileHash;
    }
    
    /**
     * Get the encrypted symmetric key
     * 
     * @return Base64-encoded encrypted AES key
     */
    public String getEncryptedSymmetricKey() {
        return encryptedSymmetricKey;
    }
    
    /**
     * Get the initialization vector
     * 
     * @return Base64-encoded IV for AES-GCM
     */
    public String getIv() {
        return iv;
    }

    @Override
    public JSONType toJSONType() {
        try {
            JSONObject json = new JSONObject();
            
            if (fileName == null) {
                System.err.println("Error: FileMetadata has null fileName");
                fileName = "unknown_file";  // Use a placeholder
            }
            json.put("fileName", fileName);
            
            json.put("fileSize", fileSize);
            
            if (fileHash == null) {
                System.err.println("Error: FileMetadata has null fileHash");
                fileHash = "unknown_hash";  // Use a placeholder
            }
            json.put("fileHash", fileHash);
            
            if (encryptedSymmetricKey == null) {
                System.err.println("Error: FileMetadata has null encryptedSymmetricKey");
                encryptedSymmetricKey = "unknown_key";  // Use a placeholder
            }
            json.put("encryptedSymmetricKey", encryptedSymmetricKey);
            
            if (iv == null) {
                System.err.println("Error: FileMetadata has null iv");
                iv = "unknown_iv";  // Use a placeholder
            }
            json.put("iv", iv);
            
            return json;
        } catch (Exception e) {
            System.err.println("Error in FileMetadata.toJSONType: " + e.getMessage());
            e.printStackTrace();
            
            // Return a minimal valid JSON as fallback
            JSONObject fallback = new JSONObject();
            fallback.put("fileName", fileName != null ? fileName : "unknown_file");
            fallback.put("fileSize", fileSize);
            fallback.put("fileHash", fileHash != null ? fileHash : "unknown_hash");
            fallback.put("encryptedSymmetricKey", "unknown_key");
            fallback.put("iv", "unknown_iv");
            return fallback;
        }
    }

    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!(obj instanceof JSONObject)) {
            throw new InvalidObjectException("Expected JSONObject for FileMetadata");
        }
        
        JSONObject json = (JSONObject) obj;
        
        // Validate required fields
        String[] requiredFields = {"fileName", "fileSize", "fileHash", "encryptedSymmetricKey", "iv"};
        for (String field : requiredFields) {
            if (!json.containsKey(field)) {
                throw new InvalidObjectException("Missing required field: " + field);
            }
        }
        
        this.fileName = json.getString("fileName");
        
        // Handle fileSize more robustly
        Object fileSizeObj = json.get("fileSize");
        if (fileSizeObj == null) {
            throw new InvalidObjectException("fileSize is null");
        }
        
        if (fileSizeObj instanceof Number) {
            this.fileSize = ((Number) fileSizeObj).longValue();
        } else {
            try {
                this.fileSize = Long.parseLong(fileSizeObj.toString());
            } catch (NumberFormatException e) {
                throw new InvalidObjectException("Invalid fileSize format: " + fileSizeObj);
            }
        }
        
        this.fileHash = json.getString("fileHash");
        this.encryptedSymmetricKey = json.getString("encryptedSymmetricKey");
        this.iv = json.getString("iv");
    }
    
    @Override
    public String serialize() {
        return toJSONType().toJSON();
    }
}