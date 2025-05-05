package pqcrypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.time.Instant;

import java.util.Map;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import javax.crypto.SecretKey;

import common.Config;
import common.Constants;
import common.Message;

import blockchain.BlockchainManager;
import blockchain.FileMetadata;
import blockchain.Transaction;


/**
 * handles file storage, encryption, and retrieval operations
 * interacts with the blockchain to record and file transactions and verify access permissions
 */
public class FileManager {

    private final Config config;
    private final CryptoManager cryptoManager;
    private final BlockchainManager blockchainManager;
    private final AuthManager authManager;

    // file storage configuration
    private final String fileStorageDirectory;
    private final long maxFileSizeBytes;

    /**
     * creates a new file manager with the specified components
     * @param config
     * @param cryptoManager
     * @param blockchainManager
     * @param authManager
     * @throws IOException
     */
    public FileManager(Config config, CryptoManager cryptoManager, BlockchainManager blockchainManager, AuthManager authManager) throws IOException {
        this.config = config;
        this.cryptoManager = cryptoManager;
        this.blockchainManager = blockchainManager;
        this.authManager = authManager;

        this.fileStorageDirectory = config.getString("storage.file_storage_directory", "./stores/files");
        this.maxFileSizeBytes = config.getInt("security.max_file_size_mb", 10) * 1024 * 1024;

        File storageDir = new File(fileStorageDirectory);
        if (!storageDir.exists()) {
            if (!storageDir.mkdirs()) {
                throw new IOException("FileManager: failed to create file storage directory: " + fileStorageDirectory);
            }
        }

        System.out.println("FileManager: initialized with storafe at " + fileStorageDirectory);
    }

    /**
     * handles file upload requests 
     * @param message
     * @param sessionId
     * @return
     */
    public Message handleFileUploadRequest(Message message, String sessionId) {
        // verify session is valid
        String username = authManager.getUsernameForSession(sessionId);
        if (username == null) {
            return message.createErrorResponse(Constants.ERROR_SESSION_EXPIRED, "AuthManager: ERROR: invalid or expired session");
        }

        // extract file data from message
        String fileName = message.getPayloadString(Constants.FIELD_FILE_NAME);
        byte[] fileData = message.getPayloadBytes(Constants.FIELD_FILE_DATA);

        if (fileName == null || fileData == null) {
            return message.createErrorResponse(Constants.ERROR_SERVER_INTERNAL, "Missing filename or file data");
        }

        // check file size
        if (fileData.length > maxFileSizeBytes) {
            return message.createErrorResponse(Constants.ERROR_FILE_TOO_LARGE, "File exceeds maximum allowed size");
        }

        try {
            // calculate file hash for identification
            String fileHash = calculateFileHash(fileData);

            // check if file already exists  in blockchain
            if (blockchainManager.fileExists(fileHash) && !config.getBoolean("blockchain.allow_file_overwrite", false)) {
                return message.createErrorResponse(Constants.ERROR_FILE_ACCESS_DENIED, "File with same content already exists");
            }

            // generate uniques storage filename
            String storageFileName = UUID.randomUUID().toString();

            // ecnrypt file
            FileEncryptionResult encryptionResult = cryptoManager.encryptFile(fileData, username.getBytes()); // usrname used as associated data for authentication

            // save encrypted file to storage
            String filePath = saveFile(storageFileName, encryptionResult.getEncryptedData());
            System.out.println("FileManager: saved encrypted file to: " + filePath);

            // create file metadata
            FileMetadata metadata = new FileMetadata(fileName, fileHash, fileData.length, storageFileName, 
                                                    Base64.getEncoder().encodeToString(encryptionResult.getFileKey().getEncoded()), 
                                                    username, Instant.now().getEpochSecond());

            // create blockchain transaction
            Transaction transaction = new Transaction(username, "UPLOAD", metadata, Instant.now().getEpochSecond());

            // sign transaction with user's credentials 
            byte[] transactionData = transaction.getDataToSign();
            byte[] signature = cryptoManager.sign(transactionData);
            transaction.setSignature(signature);

            // add transaction to blockchain
            blockchainManager.addTransaction(transaction);

            // create success response
            Message response = message.createResponse("UPLOAD_SUCCESS");
            response.setNonce(cryptoManager.generateNonce());
            response.addPayload("file_hash", fileHash);

            //  sign the response
            byte[] responseData = response.getDataToSign();
            byte[] responseSignature = cryptoManager.sign(responseData);
            response.setSignature(responseSignature);

            return response;
        } catch (Exception e) {
            System.err.println("FileManager: file upload error: " + e.getMessage());
            e.printStackTrace();
            return message.createErrorResponse(Constants.ERROR_SERVER_INTERNAL, "File upload failed: " + e.getMessage());
        }
    }

    public Message handleFileDownloadRequest(Message message, String sessionId) {
        // verify session is valid
        String username = authManager.getUsernameForSession(sessionId);
        if (username == null) {
            return message.createErrorResponse(Constants.ERROR_SESSION_EXPIRED, "FileManager: invalid or expired session");
        }

        // extract file identifier from message
        String fileHash = message.getPayloadString(Constants.FIELD_FILE_HASH);

        if (fileHash == null) {
            return message.createErrorResponse(Constants.ERROR_FILE_NOT_FOUND, "FileManager: Missing file hash");
        }

        try {
            // find file in blockchain
            Transaction transaction = blockchainManager.findLatestFileTransaction(fileHash);
            if (transaction == null) {
                return message.createErrorResponse(Constants.ERROR_FILE_NOT_FOUND, "File not found in blockchain");
            }

            FileMetadata metadata = transaction.getFileMetadata();

            // check access permissions
            if (!hasAccessPermission(username, metadata)) {
                return message.createErrorResponse(Constants.ERROR_FILE_ACCESS_DENIED, "FileManager: you don't have permission to access this file");
            }

            // get the encrypted file
            String storageFileName = metadata.getStorageFileName();
            byte[] encryptedFileData = loadFile(storageFileName);
            
            if (encryptedFileData == null) {
                return message.createErrorResponse(Constants.ERROR_FILE_NOT_FOUND, "FileManager: file data not found on server");
            }

            // decode the file key from metadata
            byte[] keyBytes = Base64.getDecoder().decode(metadata.getEncryptedKey());
            SecretKey fileKey = cryptoManager.convertBytesToKey(keyBytes);

            // decrypt the file
            byte[] fileData = cryptoManager.decryptFile(encryptedFileData, fileKey, username.getBytes());

            // verify file integrity
            String calculatedHash = calculateFileHash(fileData);
            if (!calculatedHash.equals(fileHash)) {
                return message.createErrorResponse(Constants.ERROR_FILE_ACCESS_DENIED, "FileManager: MFile integrity check failed");
            }

            // create success response
            Message response = message.createResponse("DOWNLOAD_SUCCESS");
            response.setNonce(cryptoManager.generateNonce());
            response.addPayload(Constants.FIELD_FILE_NAME, metadata.getFileName());
            response.addPayload(Constants.FIELD_FILE_DATA, fileData);
            
            // sign the reponse
            byte[] responseData = response.getDataToSign();
            byte[] responseSignature = cryptoManager.sign(responseData);
            response.setSignature(responseSignature);

            return response; 
        } catch (Exception e) {
            System.err.println("FileMananger: file downlaod error: " + e.getMessage());
            e.printStackTrace();

            return message.createErrorResponse(Constants.ERROR_SERVER_INTERNAL, "FileManager: file download failed: " + e.getMessage());
        }
    }

    /**
     * handles file listing request
     * @param message
     * @param sessionId
     * @return
     */
    public Message handleFileListRequest(Message message, String sessionId) {
        // verfiy session is valid
        String username = authManager.getUsernameForSession(sessionId);
        if (username == null) {
            return message.createErrorResponse(Constants.ERROR_SESSION_EXPIRED, "FileManager: ERROR: invalid or expired session");
        }

        try {
            // get all file transactions from blockchain
            List<Transaction> transactions = blockchainManager.getAllFileTransactions();
            List<FileMetadata> accessibleFiles = new ArrayList<>();

            // filter for files the user can access
            for (Transaction tx : transactions) {
                if (tx.getType().equals("UPLOAD")) {
                    FileMetadata metadata = tx.getFileMetadata();
                    if (hasAccessPermission(username, metadata)) {
                        accessibleFiles.add(metadata);
                    }
                }
            }

            // create success response
            Message response = message.createResponse("FILE_LIST");
            response.setNonce(cryptoManager.generateNonce());

            // build file list in payload
            List<Map<String, Object>> fileList = new ArrayList<>();
            for (FileMetadata metadata : accessibleFiles) {
                Map<String, Object> fileInfo = new HashMap<>();
                fileInfo.put("name", metadata.getFileName());
                fileInfo.put("hash", metadata.getFileHash());
                fileInfo.put("size", metadata.getFileSize());
                fileInfo.put("owner", metadata.getOwner());
                fileInfo.put("timestamp", metadata.getTimeStamp());
                fileList.add(fileInfo);
            }

            response.addPayload("files", fileList);

            // sign the response
            byte[] responseData = response.getDataToSign();
            byte[] responseSignature = cryptoManager.sign(responseData);
            response.setSignature(responseSignature);

            return response;

        } catch (Exception e) {
            System.err.println("FileManager: file list error: " + e.getMessage());
            e.printStackTrace();

            return message.createErrorResponse(Constants.ERROR_SERVER_INTERNAL, "FileManager: file listing failed: " + e.getMessage());   
        }
    }

    /**
     * calculates a hash for a file using SHA3-512
     * @param fileData
     * @return
     * @throws NoSuchAlgorithmException
     */
    private String calculateFileHash(byte[] fileData) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance(Constants.HASH_ALGORITHM);
        byte[] digest = md.digest(fileData);

        // convert to hex string
        StringBuilder hexString = new StringBuilder();
        for (byte b : digest) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    /**
     * saves an encrypted file to storage
     * @param storageFileName
     * @param encryptedFileData
     * @return
     * @throws IOException
     */
    private String saveFile(String storageFileName, byte[] encryptedFileData) throws IOException {
        Path filePath = Paths.get(fileStorageDirectory, storageFileName); 

        try (FileOutputStream output = new FileOutputStream(filePath.toFile())) {
            output.write(encryptedFileData);
        }
        return filePath.toString();
    }

    /**
     * loads an encrypted file from storage
     * @param storageFileName
     * @return
     * @throws IOException
     */
    private byte[] loadFile(String storageFileName) throws IOException {
        Path filePath = Paths.get(fileStorageDirectory, storageFileName);
        File file = filePath.toFile();

        if (!file.exists() || !file.isFile()) {
            System.err.println("FileManager: file doesnt exist or is somehow corrupted");
            return null;
        }

        try (FileInputStream input = new FileInputStream(file)) {
            return input.readAllBytes();
        }
    }

    /**
     * checks if a user has permission to access a file
     * * as of now only the owner can access their files
     * @param usrname
     * @param metadata
     * @return
     */
    private boolean hasAccessPermission(String username, FileMetadata metadata) {
        return username.equals(metadata.getOwner());
    }

    /**
     * delets a file from storage
     * @param storageFileName
     * @return
     */
    public boolean deleteFile(String storageFileName) {
        Path filePath = Paths.get(fileStorageDirectory, storageFileName);
        try {
            return Files.deleteIfExists(filePath);
        } catch (IOException e) {
            System.err.println("FileManager: failed to delete file: " + e.getMessage());
            return false;
        }
    }

    /**
     * performs cleanup of orphaned files not referenced in the blockchain
     * @return
     */
    public int cleanupOrphanedFiles() {
        int cleanedCount = 0;

        try {
            // get all files in storage directory
            File storageDir = new File(fileStorageDirectory);
            File[] files = storageDir.listFiles();

            if (files == null) {
                System.out.println("FileManager: cleanupOrphanedFiles -> no files found");
                return 0;
            }

            // get all storage filenames from blockchain
            List<String> validStorageFileNames = new ArrayList<>();
            List<Transaction> transactions = blockchainManager.getAllFileTransactions();
            for (Transaction tx : transactions) {
                if (tx.getType().equals("UPLOAD")) {
                    FileMetadata metadata = tx.getFileMetadata();
                    validStorageFileNames.add(metadata.getStorageFileName());
                }
            }

            // delete files not referenced in blockchain
            for (File file : files) {
                if (file.isFile() && !validStorageFileNames.contains(file.getName())) {
                    if (file.delete()) {
                        cleanedCount++;
                    }
                }
            }
        } catch (Exception e) {
            System.err.println("FileManager: cleanup error " + e.getMessage());
        }

        System.out.println("FileManager: cleaned up " + cleanedCount + " orphaned files");
        return cleanedCount;
    }

}
