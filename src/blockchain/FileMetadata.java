package blockchain;

import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;

import java.util.ArrayList;
import java.util.List;

public class FileMetadata {

    private String fileName;
    private long fileSize;
    private String fileType;
    private String encryptedSymmetricKey; // base64-encoded AES key
    private String fileHash;              // SHA3-256, base64
    private String uploaderId;
    private List<String> allowedUsers;    // user IDs allowed access

    // Constructor
    public FileMetadata(String fileName, long fileSize, String fileType,
                        String encryptedSymmetricKey, String fileHash,
                        String uploaderId, List<String> allowedUsers) {
        this.fileName = fileName;
        this.fileSize = fileSize;
        this.fileType = fileType;
        this.encryptedSymmetricKey = encryptedSymmetricKey;
        this.fileHash = fileHash;
        this.uploaderId = uploaderId;
        this.allowedUsers = allowedUsers;
    }

    // Serialize FileMetadata to JSON
    public JSONObject toJSON() {
        JSONObject obj = new JSONObject();
        obj.put("fileName", fileName);
        obj.put("fileSize", fileSize);
        obj.put("fileType", fileType);
        obj.put("encryptedSymmetricKey", encryptedSymmetricKey);
        obj.put("fileHash", fileHash);
        obj.put("uploaderId", uploaderId);

        JSONArray allowedArray = new JSONArray();
        for (String user : allowedUsers) {
            allowedArray.add(user);
        }
        obj.put("allowedUsers", allowedArray);

        return obj;
    }

    // Deserialize from JSON
    public static FileMetadata fromJSON(String json) throws Exception {
        JSONObject obj = new JSONObject();

        String fileName = obj.getString("fileName");
        long fileSize = ((Number) obj.get("fileSize")).longValue();
        String fileType = obj.getString("fileType");
        String encryptedKey = obj.getString("encryptedSymmetricKey");
        String fileHash = obj.getString("fileHash");
        String uploaderId = obj.getString("uploaderId");

        JSONArray allowedArray = obj.getArray("allowedUsers");
        List<String> allowedUsers = new ArrayList<>();
        for (int i = 0; i < allowedArray.size(); i++) {
            allowedUsers.add(allowedArray.getString(i));
        }

        return new FileMetadata(fileName, fileSize, fileType, encryptedKey, fileHash, uploaderId, allowedUsers);
    }

    // Optional: Validate metadata (basic structure & presence)
    public boolean isValid() {
        return fileName != null && !fileName.isEmpty()
            && fileSize > 0
            && fileType != null && !fileType.isEmpty()
            && encryptedSymmetricKey != null && !encryptedSymmetricKey.isEmpty()
            && fileHash != null && !fileHash.isEmpty()
            && uploaderId != null && !uploaderId.isEmpty()
            && allowedUsers != null;
    }

    // Getters
    public String getFileName() {
        return fileName;
    }

    public long getFileSize() {
        return fileSize;
    }

    public String getFileType() {
        return fileType;
    }

    public String getEncryptedSymmetricKey() {
        return encryptedSymmetricKey;
    }

    public String getFileHash() {
        return fileHash;
    }

    public String getUploaderId() {
        return uploaderId;
    }

    public List<String> getAllowedUsers() {
        return allowedUsers;
    }
}
