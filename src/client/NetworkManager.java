package client;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.Map;

import common.Config;
import common.Constants;
import common.JsonParser;
import common.Message;
import merrimackutil.json.types.JSONObject;

/**
 * Manages network communication with the server.
 */
public class NetworkManager {
    private Socket socket;
    private BufferedReader in;
    private PrintWriter out;
    private Config config;
    private CryptoManager cryptoManager;
    private String sessionId;
    
    /**
     * Create a new NetworkManager
     * 
     * @param config Client configuration
     * @param cryptoManager Client's crypto manager
     */
    public NetworkManager(Config config, CryptoManager cryptoManager) {
        this.config = config;
        this.cryptoManager = cryptoManager;
    }
    
    /**
     * Connect to the server
     * 
     * @param host Server hostname
     * @param port Server port
     * @return true if connection successful
     * @throws IOException If connection fails
     */
    public boolean connect(String host, int port) throws IOException {
        try {
            // Create socket
            socket = new Socket(host, port);
            
            // Set timeout
            int timeout = config.getInt("server.timeout_ms", Constants.SOCKET_TIMEOUT);
            socket.setSoTimeout(timeout);
            
            // Create streams
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);
            
            // Perform key exchange
            return performKeyExchange();
        } catch (Exception e) {
            // Clean up if connection fails
            close();
            throw new IOException("Failed to connect: " + e.getMessage(), e);
        }
    }
    
    /**
     * Disconnect from the server
     */
    public void disconnect() {
        try {
            if (socket != null && socket.isConnected()) {
                // Send goodbye message
                Message goodbye = new Message(Constants.MSG_TYPE_GOODBYE);
                
                // Add session ID to the header
                if (sessionId != null) {
                    goodbye.setHeader("sessionId", sessionId);
                }
                
                sendMessage(goodbye);
            }
        } catch (Exception e) {
            System.err.println("Error sending goodbye: " + e.getMessage());
        } finally {
            close();
        }
    }
    
    /**
     * Close socket and streams
     */
    private void close() {
        try {
            if (in != null) in.close();
            if (out != null) out.close();
            if (socket != null) socket.close();
        } catch (IOException e) {
            System.err.println("Error closing connection: " + e.getMessage());
        }
    }
    
    /**
     * Perform key exchange with the server
     * 
     * @return true if key exchange successful
     * @throws Exception If key exchange fails
     */
    private boolean performKeyExchange() throws Exception {
        // Generate key pair if not already done
        if (cryptoManager.getKyberPublicKey() == null) {
            cryptoManager.generateKeyPairs();
        }
        
        // Send HELLO message with public key
        Message hello = new Message(Constants.MSG_TYPE_HELLO);
        hello.setPayload("publicKey", cryptoManager.getKyberPublicKey());
        hello.setPayload("clientId", config.getString("client_id", "client"));
        
        Message response = sendAndReceive(hello);
        
        if (response == null || !Constants.MSG_TYPE_HELLO.equals(response.getType())) {
            return false;
        }
        
        // Process server response
        String ciphertext = response.getPayloadAsString("ciphertext");
        String serverPublicKey = response.getPayloadAsString("serverPublicKey");
        sessionId = response.getPayloadAsString("sessionId");
        
        if (ciphertext == null || serverPublicKey == null || sessionId == null) {
            return false;
        }
        
        // Decapsulate shared secret
        cryptoManager.processServerKeyExchange(ciphertext, serverPublicKey);
        
        return true;
    }
    
    /**
     * Register a new user
     * 
     * @param username Username
     * @param password Password
     * @param kyberPublicKey Kyber public key
     * @param dilithiumPublicKey Dilithium public key
     * @return Server response
     * @throws Exception If registration fails
     */
    public Message registerUser(String username, String password, 
                               String kyberPublicKey, String dilithiumPublicKey) throws Exception {

        // Create registration message
        Message registerMsg = new Message(Constants.MSG_TYPE_AUTH_REQUEST);
        registerMsg.setPayload("action", "register");
        registerMsg.setPayload("username", username);
        
        // Encrypt sensitive data - must include a TOTP code for the format to match
        // Format must be exactly username:password:totpCode
        String authData = username + ":" + password + ":123456"; // Add default TOTP code
        Map<String, String> encryptedData = cryptoManager.encryptWithSessionKey(authData.getBytes());
        
        registerMsg.setPayload("encryptedData", encryptedData.get("ciphertext"));
        registerMsg.setPayload("iv", encryptedData.get("iv"));
        registerMsg.setPayload("kyberPublicKey", kyberPublicKey);
        registerMsg.setPayload("dilithiumPublicKey", dilithiumPublicKey);
        
        // Add current session ID to the header
        if (sessionId != null) {
            registerMsg.setHeader("sessionId", sessionId);
        }
        
        // Send and receive response
        return sendAndReceive(registerMsg);
    }
    
    /**
     * Authenticate a user
     * 
     * @param username Username
     * @param password Password
     * @param totpCode TOTP code
     * @return Server response
     * @throws Exception If authentication fails
     */
    public Message authenticate(String username, String password, String totpCode) throws Exception {
        // Create authentication message
        Message authMsg = new Message(Constants.MSG_TYPE_AUTH_REQUEST);
        authMsg.setPayload("action", "login");
        authMsg.setPayload("username", username);
        
        // Encrypt sensitive data with proper encoding - format must be username:password:totpCode
        String authData = username + ":" + password + ":" + totpCode;
        Map<String, String> encryptedData = cryptoManager.encryptWithSessionKey(authData.getBytes());
        
        authMsg.setPayload("encryptedData", encryptedData.get("ciphertext"));
        authMsg.setPayload("iv", encryptedData.get("iv"));
        
        // Add current session ID to the header
        if (sessionId != null) {
            authMsg.setHeader("sessionId", sessionId);
        }
        
        // Send and receive response
        Message response = sendAndReceive(authMsg);
        
        if (response != null && Constants.MSG_TYPE_AUTH_RESPONSE.equals(response.getType())) {
            // Update session ID if provided
            String newSessionId = response.getPayloadAsString("sessionId");
            if (newSessionId != null) {
                this.sessionId = newSessionId;
                System.out.println("Session ID updated to: " + newSessionId);
            }
        }
        
        return response;
    }
    
    /**
     * Upload a file to the server
     * 
     * @param fileName The file name
     * @param fileData The file data
     * @return Server response
     * @throws Exception If upload fails
     */
    public Message uploadFile(String fileName, byte[] fileData) throws Exception {
        if (sessionId == null) {
            throw new IllegalStateException("Cannot upload file: Not authenticated");
        }
        
        System.out.println("Encrypting file...");
        
        // Create upload message with minimal required fields
        Message uploadMsg = new Message(Constants.MSG_TYPE_UPLOAD_REQUEST);
        
        // Mandatory fields first - these are the ones checked by the server
        uploadMsg.setPayload("fileName", fileName);
        
        // Encrypt file data
        Map<String, String> encryptedData = cryptoManager.encryptWithSessionKey(fileData);
        uploadMsg.setPayload("encryptedData", encryptedData.get("ciphertext"));
        uploadMsg.setPayload("iv", encryptedData.get("iv"));
        
        // Sign the file data
        String signature = cryptoManager.sign(fileData);
        uploadMsg.setPayload("signature", signature);
        
        // Place session ID only in the header for consistency
        uploadMsg.setHeader("sessionId", sessionId);
        
        System.out.println("Adding to blockchain... using sessionId: " + sessionId);
        
        // Send and receive response
        return sendAndReceive(uploadMsg);
    }
    
    /**
     * Download a file from the server
     * 
     * @param fileHash Hash of the file to download
     * @return Server response
     * @throws Exception If download fails
     */
    public Message downloadFile(String fileHash) throws Exception {
        if (sessionId == null) {
            throw new IllegalStateException("Cannot download file: Not authenticated");
        }
        
        // Create download message
        Message downloadMsg = new Message(Constants.MSG_TYPE_DOWNLOAD_REQUEST);
        downloadMsg.setPayload("fileHash", fileHash);
        
        // Add session ID to the header
        downloadMsg.setHeader("sessionId", sessionId);
        
        // Send and receive response
        return sendAndReceive(downloadMsg);
    }
    
    /**
     * List available files
     * 
     * @param userOnly Only show files uploaded by the current user
     * @return Server response
     * @throws Exception If listing fails
     */
    public Message listFiles(boolean userOnly) throws Exception {
        if (sessionId == null) {
            throw new IllegalStateException("Cannot list files: Not authenticated");
        }
        
        // Create list message
        Message listMsg = new Message(Constants.MSG_TYPE_LIST_REQUEST);
        listMsg.setPayload("userOnly", String.valueOf(userOnly));
        
        // Add session ID to the header
        listMsg.setHeader("sessionId", sessionId);
        
        // Send and receive response
        return sendAndReceive(listMsg);
    }
    
    /**
     * Verify a file on the blockchain
     * 
     * @param fileHash Hash of the file to verify
     * @return Server response
     * @throws Exception If verification fails
     */
    public Message verifyFile(String fileHash) throws Exception {
        if (sessionId == null) {
            throw new IllegalStateException("Cannot verify file: Not authenticated");
        }
        
        // Create verify message
        Message verifyMsg = new Message(Constants.MSG_TYPE_VERIFY_REQUEST);
        verifyMsg.setPayload("fileHash", fileHash);
        
        // Add session ID to the header
        verifyMsg.setHeader("sessionId", sessionId);
        
        // Send and receive response
        return sendAndReceive(verifyMsg);
    }
    
    /**
     * Get blockchain information
     * 
     * @return Server response
     * @throws Exception If blockchain request fails
     */
    public Message getBlockchain() throws Exception {
        if (sessionId == null) {
            throw new IllegalStateException("Cannot get blockchain: Not authenticated");
        }
        
        // Create blockchain message
        Message blockchainMsg = new Message(Constants.MSG_TYPE_BLOCKCHAIN_REQUEST);
        
        // Add session ID to the header
        blockchainMsg.setHeader("sessionId", sessionId);
        
        // Send and receive response
        return sendAndReceive(blockchainMsg);
    }
    
    /**
     * Send a message and receive the response
     * 
     * @param message The message to send
     * @return The response message or null if no response
     * @throws Exception If communication fails
     */
    private Message sendAndReceive(Message message) throws Exception {
        if (socket == null || !socket.isConnected()) {
            throw new IOException("Not connected to server");
        }
        
        sendMessage(message);
        return receiveMessage();
    }
    
    /**
     * Send a message to the server
     * 
     * @param message The message to send
     * @throws Exception If sending fails
     */
    private void sendMessage(Message message) throws Exception {
        // NOTE: Session ID should be already set in the specific message-handling methods
        // either in the header or payload as needed by the server
        
        // Serialize using custom method to ensure correct format
        String messageJson = message.serialize();
        System.out.println("Sending: " + messageJson);
        
        // Send to server
        out.println(messageJson);
        out.flush();
    }
    
    /**
     * Receive a message from the server
     * 
     * @return The received message or null if no message
     * @throws Exception If receiving fails
     */
    private Message receiveMessage() throws Exception {
        try {
            String messageJson = in.readLine();
            if (messageJson == null) {
                throw new IOException("Connection closed by server");
            }
            
            System.out.println("Received: " + messageJson);
            
            try {
                // First, try direct Message deserialization
                Message message = new Message();
                message.deserialize(messageJson);
                return message;
            } catch (Exception e) {
                // If direct deserialization fails, try our custom parser wrapper
                try {
                    JSONObject jsonObj = JsonParser.parseObject(messageJson);
                    if (jsonObj == null) {
                        throw new IOException("Invalid JSON from server");
                    }
                    return new Message(jsonObj);
                } catch (Exception e2) {
                    // Last resort - manual parsing for simple cases
                    return parseMessageManually(messageJson);
                }
            }
        } catch (SocketTimeoutException e) {
            throw new IOException("Connection timed out waiting for server response", e);
        }
    }
    
    /**
     * Parse a message manually when all other methods fail
     */
    private Message parseMessageManually(String messageJson) {
        Message message = new Message();
        
        try {
            // Simple regex extraction of key fields
            // Extract type
            String typeRegex = "\"type\":\"([^\"]+)\"";
            java.util.regex.Pattern typePattern = java.util.regex.Pattern.compile(typeRegex);
            java.util.regex.Matcher typeMatcher = typePattern.matcher(messageJson);
            if (typeMatcher.find()) {
                message.setType(typeMatcher.group(1));
            }
            
            // Extract version
            String versionRegex = "\"version\":\"([^\"]+)\"";
            java.util.regex.Pattern versionPattern = java.util.regex.Pattern.compile(versionRegex);
            java.util.regex.Matcher versionMatcher = versionPattern.matcher(messageJson);
            if (versionMatcher.find()) {
                message.setVersion(versionMatcher.group(1));
            }
            
            // Extract nonce
            String nonceRegex = "\"nonce\":\"([^\"]+)\"";
            java.util.regex.Pattern noncePattern = java.util.regex.Pattern.compile(nonceRegex);
            java.util.regex.Matcher nonceMatcher = noncePattern.matcher(messageJson);
            if (nonceMatcher.find()) {
                message.setNonce(nonceMatcher.group(1));
            }
            
            // Extract session ID (if present)
            String sessionIdRegex = "\"sessionId\":\"([^\"]+)\"";
            java.util.regex.Pattern sessionIdPattern = java.util.regex.Pattern.compile(sessionIdRegex);
            java.util.regex.Matcher sessionIdMatcher = sessionIdPattern.matcher(messageJson);
            if (sessionIdMatcher.find()) {
                message.setPayload("sessionId", sessionIdMatcher.group(1));
                
                // Update local session ID
                this.sessionId = sessionIdMatcher.group(1);
            }
            
            // Extract ciphertext (if present)
            String ciphertextRegex = "\"ciphertext\":\"([^\"]+)\"";
            java.util.regex.Pattern ciphertextPattern = java.util.regex.Pattern.compile(ciphertextRegex);
            java.util.regex.Matcher ciphertextMatcher = ciphertextPattern.matcher(messageJson);
            if (ciphertextMatcher.find()) {
                message.setPayload("ciphertext", ciphertextMatcher.group(1));
            }
            
            // Extract server public key (if present)
            String pubKeyRegex = "\"serverPublicKey\":\"([^\"]+)\"";
            java.util.regex.Pattern pubKeyPattern = java.util.regex.Pattern.compile(pubKeyRegex);
            java.util.regex.Matcher pubKeyMatcher = pubKeyPattern.matcher(messageJson);
            if (pubKeyMatcher.find()) {
                message.setPayload("serverPublicKey", pubKeyMatcher.group(1));
            }
            
            // Add more extractors for other common fields as needed
            
            return message;
        } catch (Exception e) {
            System.err.println("Error in manual message parsing: " + e.getMessage());
            // Return a minimal valid message
            return new Message("ERROR");
        }
    }
}