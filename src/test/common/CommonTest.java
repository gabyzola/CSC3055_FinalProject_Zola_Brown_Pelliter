package test.common;

import java.io.File;
import java.io.FileWriter;
import java.util.Base64;
import merrimackutil.json.types.JSONObject;

import common.Config;
import common.Constants;
import common.Message;
import common.User;

public class CommonTest {
    // Simple assertion method
    private static void assertTrue(boolean condition, String message) {
        if (!condition) {
            System.err.println("FAILED: " + message);
            Thread.dumpStack();
        } else {
            System.out.println("PASSED: " + message);
        }
    }
    
    // Simple equality assertion
    private static void assertEquals(Object expected, Object actual, String message) {
        boolean isEqual = (expected == null && actual == null) || 
                         (expected != null && expected.equals(actual));
        assertTrue(isEqual, message + " - Expected: " + expected + ", Actual: " + actual);
    }
    
    public static void main(String[] args) {
        try {
            // Create a test config file
            File testConfigFile = File.createTempFile("test-config", ".json");
            
            JSONObject testConfig = new JSONObject();
            JSONObject server = new JSONObject();
            server.put("port", 5001);
            server.put("host", "127.0.0.1");
            server.put("timeout_ms", 30000);
            testConfig.put("server", server);
            
            JSONObject storage = new JSONObject();
            storage.put("download_directory", "./downloads");
            storage.put("upload_buffer_size", 1024000);
            testConfig.put("storage", storage);
            
            try (FileWriter writer = new FileWriter(testConfigFile)) {
                writer.write(testConfig.toJSON());
            }
            
            System.out.println("========== Testing Config ==========");
            testConfig(testConfigFile.getAbsolutePath());
            
            System.out.println("\n========== Testing User ==========");
            testUser();
            
            System.out.println("\n========== Testing Message ==========");
            testMessage();
            
            System.out.println("\n========== Testing Constants ==========");
            testConstants();
            
            // Clean up
            testConfigFile.delete();
            
            System.out.println("\nAll tests completed!");
        } catch (Exception e) {
            System.err.println("Test failed with exception: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static void testConfig(String configPath) throws Exception {
        Config config = Config.getInstance(configPath);
        
        assertEquals(5001, config.getInt("server.port", 0), "server.port value");
        assertEquals("127.0.0.1", config.getString("server.host", ""), "server.host value");
        assertEquals(30000, config.getInt("server.timeout_ms", 0), "server.timeout_ms value");
        assertEquals("./downloads", config.getString("storage.download_directory", ""), "storage.download_directory value");
        assertEquals(1024000, config.getInt("storage.upload_buffer_size", 0), "storage.upload_buffer_size value");
        
        // Test default values
        assertEquals("default", config.getString("nonexistent.key", "default"), "Default string value");
        assertEquals(42, config.getInt("nonexistent.key", 42), "Default int value");
        
        // Test validation
        String[] requiredKeys = {"server.port", "server.host", "storage.download_directory"};
        try {
            config.validate(requiredKeys);
            System.out.println("PASSED: Config validation with valid keys");
        } catch (IllegalArgumentException e) {
            System.err.println("FAILED: Config validation with valid keys");
        }
        
        try {
            String[] invalidKeys = {"server.port", "nonexistent.key"};
            config.validate(invalidKeys);
            System.err.println("FAILED: Config validation with invalid keys");
        } catch (IllegalArgumentException e) {
            System.out.println("PASSED: Config validation with invalid keys");
        }
    }
    
    private static void testUser() throws Exception {
        User user = new User("testuser", "password123");
        
        assertEquals("testuser", user.getUsername(), "Username");
        assertTrue(user.getTotpSecret() != null, "TOTP secret is not null");
        assertTrue(user.verifyPassword("password123"), "Password verification for correct password");
        assertTrue(!user.verifyPassword("wrongpassword"), "Password verification for wrong password");
        
        // Test serialization
        JSONObject json = (JSONObject) user.toJSONType();
        
        User deserializedUser = new User(json);
        assertEquals(user.getUsername(), deserializedUser.getUsername(), "Username after deserialization");
        assertEquals(user.getTotpSecret(), deserializedUser.getTotpSecret(), "TOTP secret after deserialization");
        assertTrue(deserializedUser.verifyPassword("password123"), "Password verification after deserialization");
        
        // Test key setting
        String fakePublicKey = Base64.getEncoder().encodeToString("fakekey".getBytes());
        user.setKyberPublicKey(fakePublicKey);
        user.setDilithiumPublicKey(fakePublicKey);
        
        assertEquals(fakePublicKey, user.getKyberPublicKey(), "Kyber public key");
        assertEquals(fakePublicKey, user.getDilithiumPublicKey(), "Dilithium public key");
    }
    
    private static void testMessage() throws Exception {
        Message message = new Message(Constants.MSG_TYPE_HELLO);
        
        assertEquals(Constants.MSG_TYPE_HELLO, message.getType(), "Message type");
        assertEquals(Constants.PROTOCOL_VERSION, message.getVersion(), "Protocol version");
        assertTrue(message.getNonce() != null, "Nonce is not null");
        
        // Test headers
        message.setHeader("session_id", "session123");
        message.setHeader("timestamp", 1234567890);
        
        assertEquals("session123", message.getHeaderAsString("session_id"), "String header");
        assertEquals(1234567890, message.getHeaderAsInt("timestamp", 0), "Integer header");
        assertEquals(42, message.getHeaderAsInt("nonexistent", 42), "Default integer header"); 
        
        // Test payload
        message.setPayload("username", "alice");
        message.setPayload("file_size", 1024);
        
        assertEquals("alice", message.getPayloadAsString("username"), "String payload");
        assertEquals(1024, message.getPayloadAsInt("file_size", 0), "Integer payload");
        assertEquals(42, message.getPayloadAsInt("nonexistent", 42), "Default integer payload");
        
        // Test signing content
        String contentForSigning = message.getContentForSigning();
        assertTrue(contentForSigning != null, "Content for signing is not null");
        
        // Test signature
        String fakeSignature = Base64.getEncoder().encodeToString("signature".getBytes());
        message.setSignature(fakeSignature);
        assertEquals(fakeSignature, message.getSignature(), "Signature");
        
        // Test serialization
        JSONObject json = (JSONObject) message.toJSONType();
        
        Message deserializedMessage = new Message();
        deserializedMessage.deserialize(json);
        
        assertEquals(message.getType(), deserializedMessage.getType(), "Type after deserialization");
        assertEquals(message.getNonce(), deserializedMessage.getNonce(), "Nonce after deserialization");
        assertEquals(message.getHeaderAsString("session_id"), deserializedMessage.getHeaderAsString("session_id"), 
                    "Header after deserialization");
        assertEquals(message.getPayloadAsString("username"), deserializedMessage.getPayloadAsString("username"), 
                    "Payload after deserialization");
        assertEquals(message.getSignature(), deserializedMessage.getSignature(), "Signature after deserialization");
        
        // Test error message
        Message errorMessage = Message.createErrorMessage(
                Constants.ERROR_AUTHENTICATION_FAILED, "Authentication failed");
        
        assertEquals(Constants.MSG_TYPE_ERROR, errorMessage.getType(), "Error message type");
        assertEquals(Constants.ERROR_AUTHENTICATION_FAILED, errorMessage.getPayloadAsInt("code", 0), "Error code");
        assertEquals("Authentication failed", errorMessage.getPayloadAsString("message"), "Error message");
    }
    
    private static void testConstants() {
        // Just verify a few constants are accessible
        assertTrue(Constants.PROTOCOL_VERSION != null, "Protocol version is not null");
        assertTrue(Constants.NONCE_SIZE > 0, "Nonce size is positive");
        assertEquals("SHA3-512", Constants.HASH_ALGORITHM, "Hash algorithm");
        assertEquals("AES/GCM/NoPadding", Constants.AES_MODE, "AES mode");
    }
}