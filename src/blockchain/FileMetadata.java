package blockchain;

import merrimackutil.json.types.JSONArray;
import merrimackutil.json.types.JSONObject;

import java.util.ArrayList;
import java.util.List;

/**
 * Stores metadata about files in the blockchain
 */
public class FileMetadata {
    private String fileName;
    private String fileHash;
    private long fileSize;
    private String storageFileName;
    private String encryptedKey;
    private String owner;
    private long timeStamp;
    private List<String> allowedUsers;

    /**
     * Constructor for file metadata
     * @param fileName Original file name
     * @param fileHash Hash of the file
     * @param fileSize Size of the file in bytes
     * @param storageFileName Name of file in storage
     * @param encryptedKey Encrypted symmetric key
     * @param owner Owner of the file
     * @param timeStamp Upload timestamp
     */
    public FileMetadata(String fileName, String fileHash, long fileSize, String storageFileName, 
                        String encryptedKey, String owner, long timeStamp) {
        this.fileName = fileName;
        this.fileHash = fileHash;
        this.fileSize = fileSize;
        this.storageFileName = storageFileName;
        this.encryptedKey = encryptedKey;
        this.owner = owner;
        this.timeStamp = timeStamp;
        this.allowedUsers = new ArrayList<>();
        this.allowedUsers.add(owner); // Owner always has access
    }

    /**
     * Private constructor for deserialization
     */
    private FileMetadata() {
        this.allowedUsers = new ArrayList<>();
    }

    /**
     * Convert to JSONObject
     * @return JSON representation
     */
    public JSONObject toJSONObject() {
        JSONObject obj = new JSONObject();
        obj.put("fileName", fileName);
        obj.put("fileHash", fileHash);
        obj.put("fileSize", fileSize);
        obj.put("storageFileName", storageFileName);
        obj.put("encryptedKey", encryptedKey);
        obj.put("owner", owner);
        obj.put("timeStamp", timeStamp);

        JSONArray allowedArray = new JSONArray();
        for (String user : allowedUsers) {
            allowedArray.add(user);
        }
        obj.put("allowedUsers", allowedArray);

        return obj;
    }

    /**
     * Deserialize from JSON
     * @param jsonObj JSON object to deserialize
     * @return FileMetadata object
     */
    public static FileMetadata fromJSON(JSONObject jsonObj) {
        FileMetadata metadata = new FileMetadata();
        
        metadata.fileName = jsonObj.getString("fileName");
        metadata.fileHash = jsonObj.getString("fileHash");
        
        Number fileSize = (Number) jsonObj.get("fileSize");
        metadata.fileSize = fileSize.longValue();
        
        metadata.storageFileName = jsonObj.getString("storageFileName");
        metadata.encryptedKey = jsonObj.getString("encryptedKey");
        metadata.owner = jsonObj.getString("owner");
        
        Number timestamp = (Number) jsonObj.get("timeStamp");
        metadata.timeStamp = timestamp.longValue();

        JSONArray allowedArray = jsonObj.getArray("allowedUsers");
        if (allowedArray != null) {
            for (int i = 0; i < allowedArray.size(); i++) {
                String user = allowedArray.getString(i);
                if (user != null) {
                    metadata.allowedUsers.add(user);
                }
            }
        }

        return metadata;
    }

    /**
     * Add a user to the allowed list
     * @param username User to add
     */
    public void addAllowedUser(String username) {
        if (!allowedUsers.contains(username)) {
            allowedUsers.add(username);
        }
    }

    /**
     * Remove a user from the allowed list
     * @param username User to remove
     */
    public void removeAllowedUser(String username) {
        // Owner always has access
        if (!username.equals(owner)) {
            allowedUsers.remove(username);
        }
    }

    /**
     * Check if a user has access
     * @param username User to check
     * @return true if allowed
     */
    public boolean hasAccess(String username) {
        return allowedUsers.contains(username);
    }

    // Getters
    public String getFileName() {
        return fileName;
    }

    public String getFileHash() {
        return fileHash;
    }

    public long getFileSize() {
        return fileSize;
    }

    public String getStorageFileName() {
        return storageFileName;
    }

    public String getEncryptedKey() {
        return encryptedKey;
    }

    public String getOwner() {
        return owner;
    }

    public long getTimeStamp() {
        return timeStamp;
    }

    public List<String> getAllowedUsers() {
        return new ArrayList<>(allowedUsers);
    }
}