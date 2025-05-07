// package test.pqcrypto;

// import java.io.File;
// import java.nio.charset.StandardCharsets;
// import java.util.Map;

// import common.Config;
// import pqcrypto.CryptoManager;

// public class ServerCryptoTest {
//     // Simple assertion method
//     private static void assertTrue(boolean condition, String message) {
//         if (!condition) {
//             System.err.println("FAILED: " + message);
//             Thread.dumpStack();
//         } else {
//             System.out.println("PASSED: " + message);
//         }
//     }
    
//     // Simple equality assertion
//     private static void assertEquals(Object expected, Object actual, String message) {
//         boolean isEqual = (expected == null && actual == null) || 
//                          (expected != null && expected.equals(actual));
//         assertTrue(isEqual, message + " - Expected: " + expected + ", Actual: " + actual);
//     }
    
//     // Simple not-null assertion
//     private static void assertNotNull(Object obj, String message) {
//         assertTrue(obj != null, message);
//     }
    
//     public static void main(String[] args) {
//         try {
//             System.out.println("========== Testing Server CryptoManager ==========");
//             testServerCryptoManager();
            
//             System.out.println("\nAll server crypto tests completed!");
//         } catch (Exception e) {
//             System.err.println("Test failed with exception: " + e.getMessage());
//             e.printStackTrace();
//         }
//     }
    
//     private static void testServerCryptoManager() throws Exception {
//         // Create a temporary config

//         System.out.println("stage 1");

//         File tempConfigFile = File.createTempFile("server-config", ".json");
//         tempConfigFile.deleteOnExit();
        
//         System.out.println("stage 2");

//         // Initialize CryptoManager with default settings
//         CryptoManager cryptoManager = new CryptoManager(Config.getInstance(true));
        
//         System.out.println("stage 3");

//         // Test server public key
//         String serverPublicKey = cryptoManager.getServerPublicKey();
//         assertNotNull(serverPublicKey, "Server public key should not be null");
        
//         System.out.println("stage 4");

//         // Test key exchange
//         pqcrypto.KyberOperations kyber = new pqcrypto.KyberOperations();
//         pqcrypto.KyberOperations.KeyPair clientKeys = kyber.generateKeyPair();

//         System.out.println("stage 5");
        
//         Map<String, String> keyExchangeResult = cryptoManager.processKeyExchange(clientKeys.getPublicKey());
//         assertNotNull(keyExchangeResult, "Key exchange result should not be null");
//         assertNotNull(keyExchangeResult.get("sessionId"), "Session ID should not be null");
//         assertNotNull(keyExchangeResult.get("ciphertext"), "Ciphertext should not be null");
        
//         String sessionId = keyExchangeResult.get("sessionId");

//         System.out.println("stage 6");
        
//         // Test session encryption/decryption
//         byte[] testData = "Test data for session encryption".getBytes(StandardCharsets.UTF_8);
//         byte[] associatedData = "Associated data".getBytes(StandardCharsets.UTF_8);
        
//         Map<String, String> encryptedData = cryptoManager.encryptForSession(sessionId, testData, associatedData);
//         assertNotNull(encryptedData, "Encrypted data should not be null");
//         assertNotNull(encryptedData.get("ciphertext"), "Ciphertext should not be null");
//         assertNotNull(encryptedData.get("iv"), "IV should not be null");
        
//         byte[] decryptedData = cryptoManager.decryptForSession(
//             sessionId, 
//             encryptedData.get("ciphertext"), 
//             encryptedData.get("iv"), 
//             associatedData
//         );

//         System.out.println("stage 7");
        
//         assertNotNull(decryptedData, "Decrypted data should not be null");
//         assertEquals(
//             new String(testData, StandardCharsets.UTF_8),
//             new String(decryptedData, StandardCharsets.UTF_8),
//             "Decrypted data should match original"
//         );
        
//         // Test data signing and verification
//         byte[] dataToSign = "Data to sign with Dilithium".getBytes(StandardCharsets.UTF_8);
//         String signature = cryptoManager.signData(dataToSign);
//         assertNotNull(signature, "Signature should not be null");
        
//         boolean verificationResult = cryptoManager.verifySignature(
//             dataToSign, 
//             signature, 
//             cryptoManager.getServerPublicKey()
//         );
        
//         assertTrue(verificationResult, "Signature verification should succeed");
        
//         // Test nonce validation
//         String nonce = java.util.Base64.getEncoder().encodeToString(new byte[16]);
//         boolean firstValidation = cryptoManager.validateNonce(nonce);
//         assertTrue(firstValidation, "First nonce validation should succeed");
        
//         boolean secondValidation = cryptoManager.validateNonce(nonce);
//         assertTrue(!secondValidation, "Second nonce validation should fail (replay)");
        
//         // Test session management
//         cryptoManager.removeSession(sessionId);
        
//         try {
//             cryptoManager.encryptForSession(sessionId, testData, null);
//             assertTrue(false, "Should have thrown exception for removed session");
//         } catch (IllegalArgumentException e) {
//             assertTrue(true, "Correctly threw exception for removed session");
//         }
//     }
// }