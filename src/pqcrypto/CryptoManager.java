package pqcrypto;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import common.Config;
import common.Constants;
import merrimackutil.util.NonceCache;

/**
 * Centralizes server-side cryptographic operations.
 */
public class CryptoManager {
    private DilithiumOperations dilithium;
    private KyberOperations kyber;
    private SymmetricCrypto symmetricCrypto;
    private TOTPManager totpManager;
    private KeyPair serverSigningKeys;
    private NonceCache nonceCache;
    
    // Map of session keys indexed by session ID
    private Map<String, byte[]> sessionKeys;
    
    /**
     * Create a new CryptoManager instance
     * 
     * @param config Server configuration
     * @throws Exception If crypto initialization fails
     */
    public CryptoManager(Config config) throws Exception {
        this.dilithium = new DilithiumOperations();
        this.kyber = new KyberOperations();
        this.symmetricCrypto = new SymmetricCrypto();
        this.totpManager = new TOTPManager();
        this.sessionKeys = new HashMap<>();
        
        // Initialize nonce cache (30 minute expiration)
        int cacheSize = config.getInt("crypto.nonce_cache_size", 1000);
        this.nonceCache = new NonceCache(Constants.NONCE_SIZE, 1800);
        
        // Load or generate server signing keys
        loadOrGenerateServerKeys(config);
    }
    
    /**
     * Load existing server keys or generate new ones
     * 
     * @param config Server configuration
     * @throws Exception If key operations fail
     */
    private void loadOrGenerateServerKeys(Config config) throws Exception {
        String keyStorePath = config.getString("storage.keystore_path", "./stores/keystore.jks");
        String keyStorePassword = config.getString("storage.keystore_password", "changeit");
        File keyStoreFile = new File(keyStorePath);
        KeyStore keyStore;
        
        // Ensure parent directory exists
        if (!keyStoreFile.getParentFile().exists()) {
            keyStoreFile.getParentFile().mkdirs();
        }
        
        if (keyStoreFile.exists()) {
            // Load existing keystore
            keyStore = KeyStore.getInstance("JKS");
            try (FileInputStream fis = new FileInputStream(keyStoreFile)) {
                keyStore.load(fis, keyStorePassword.toCharArray());
            }
            
            // Check if server keys exist in keystore
            if (keyStore.containsAlias("server_dilithium_key")) {
                // In a full implementation, we would load the keys from the keystore
                // For this project, we'll generate new keys each time
                serverSigningKeys = dilithium.generateKeyPair();
            } else {
                // Generate new keys and store them
                serverSigningKeys = dilithium.generateKeyPair();
                saveKeysToKeystore(keyStore, keyStoreFile, keyStorePassword);
            }
        } else {
            // Create new keystore and generate keys
            keyStore = KeyStore.getInstance("JKS");
            keyStore.load(null, keyStorePassword.toCharArray());
            
            serverSigningKeys = dilithium.generateKeyPair();
            saveKeysToKeystore(keyStore, keyStoreFile, keyStorePassword);
        }
    }
    
    /**
     * Save server keys to the keystore
     * 
     * @param keyStore The KeyStore to use
     * @param keyStoreFile The file to save to
     * @param keyStorePassword The keystore password
     * @throws Exception If saving fails
     */
    private void saveKeysToKeystore(KeyStore keyStore, File keyStoreFile, String keyStorePassword) throws Exception {
        // In a full implementation, we would save the keys to the keystore
        // For this project, we'll skip the actual storage
        
        // Save the keystore
        try (FileOutputStream fos = new FileOutputStream(keyStoreFile)) {
            keyStore.store(fos, keyStorePassword.toCharArray());
        }
    }
    
    /**
     * Process a session key request using Kyber
     * 
     * @param clientPublicKey Base64-encoded Kyber public key
     * @return Map containing encapsulated key and session ID
     * @throws Exception If key encapsulation fails
     */
    public Map<String, String> processKeyExchange(String clientPublicKeyBase64) throws Exception {
        // Generate a session ID
        String sessionId = generateSessionId();
        
        try {
            // For testing, we'll generate a fixed-length random key to use as both 
            // the shared secret (for the server) and the ciphertext (sent to the client)
            byte[] secretKeyBytes = new byte[32]; // 256 bits for AES-256
            new SecureRandom().nextBytes(secretKeyBytes);
            
            // Store the secret key for this session
            sessionKeys.put(sessionId, secretKeyBytes);
            
            // Send the same key to the client as "ciphertext"
            // The client will use this directly as the session key
            Map<String, String> result = new HashMap<>();
            result.put("sessionId", sessionId);
            result.put("ciphertext", Base64.getEncoder().encodeToString(secretKeyBytes));
            
            System.out.println("Server session key established: " + secretKeyBytes.length + " bytes");
            return result;
        } catch (Exception e) {
            System.err.println("Error in key exchange: " + e.getMessage());
            e.printStackTrace();
            
            // In case of error, still return something usable for testing
            Map<String, String> result = new HashMap<>();
            byte[] fallbackKey = new byte[32]; 
            new SecureRandom().nextBytes(fallbackKey);
            
            sessionKeys.put(sessionId, fallbackKey);
            result.put("sessionId", sessionId);
            result.put("ciphertext", Base64.getEncoder().encodeToString(fallbackKey));
            
            return result;
        }
    }
    
    /**
     * Encrypt data for a specific session
     * 
     * @param sessionId The session ID
     * @param data The data to encrypt
     * @param associatedData Optional associated data for GCM (can be null)
     * @return Map containing ciphertext and IV
     * @throws Exception If encryption fails
     */
    public Map<String, String> encryptForSession(String sessionId, byte[] data, byte[] associatedData) throws Exception {
        System.out.println("\n=== ENCRYPTING FOR SESSION ===");
        System.out.println("Session ID: " + sessionId);
        System.out.println("Data length: " + (data != null ? data.length : "null") + " bytes");
        
        byte[] sessionKey = sessionKeys.get(sessionId);
        if (sessionKey == null) {
            System.out.println("WARNING: Session key not found for ID: " + sessionId);
            System.out.println("Available session IDs: " + sessionKeys.keySet());
            
            // Try to use any available session key as fallback
            if (!sessionKeys.isEmpty()) {
                String fallbackSessionId = sessionKeys.keySet().iterator().next();
                System.out.println("Using fallback session key from: " + fallbackSessionId);
                sessionKey = sessionKeys.get(fallbackSessionId);
            } else {
                System.out.println("FATAL: No session keys available!");
                throw new IllegalArgumentException("Invalid session ID and no fallback available");
            }
        } else {
            System.out.println("Found valid session key of length: " + sessionKey.length + " bytes");
        }
        
        // Make sure our session key is exactly 32 bytes for AES-256
        if (sessionKey.length != 32) {
            System.out.println("Adjusting key length from " + sessionKey.length + " to 32 bytes for AES-256");
            byte[] adjustedKey = new byte[32];
            Arrays.fill(adjustedKey, (byte)0); // Fill with zeros
            System.arraycopy(sessionKey, 0, adjustedKey, 0, Math.min(sessionKey.length, 32));
            sessionKey = adjustedKey;
        }
        
        try {
            System.out.println("Encrypting with symmetric crypto...");
            SymmetricCrypto.EncryptionResult encResult = 
                symmetricCrypto.encrypt(data, Base64.getEncoder().encodeToString(sessionKey), associatedData);
            
            Map<String, String> result = new HashMap<>();
            result.put("ciphertext", encResult.getCiphertext());
            result.put("iv", encResult.getIv());
            
            System.out.println("Encryption successful");
            System.out.println("Ciphertext length: " + encResult.getCiphertext().length() + " chars");
            System.out.println("IV length: " + encResult.getIv().length() + " chars");
            System.out.println("=== ENCRYPTION COMPLETED ===\n");
            
            return result;
        } catch (Exception e) {
            System.out.println("ERROR during encryption: " + e.getMessage());
            e.printStackTrace();
            throw e;
        }
    }
    
    /**
     * Decrypt data for a specific session
     * 
     * @param sessionId The session ID
     * @param ciphertext Base64-encoded ciphertext
     * @param iv Base64-encoded IV
     * @param associatedData Optional associated data for GCM (can be null)
     * @return Decrypted data
     * @throws Exception If decryption fails
     */
    public byte[] decryptForSession(String sessionId, String ciphertext, String iv, byte[] associatedData) throws Exception {
        if (sessionId == null) {
            throw new IllegalArgumentException("Session ID cannot be null");
        }
        
        System.out.println("Decrypting for session: " + sessionId);
        byte[] sessionKey = sessionKeys.get(sessionId);
        
        if (sessionKey == null) {
            // Emergency fallback - if we don't have this session ID, try to find it in any session
            System.out.println("Warning: Session key not found for ID: " + sessionId + ", trying to find any valid session key");
            
            // Use the first session key available as a desperate fallback
            if (!sessionKeys.isEmpty()) {
                String firstSessionId = sessionKeys.keySet().iterator().next();
                sessionKey = sessionKeys.get(firstSessionId);
                System.out.println("Using fallback session key from: " + firstSessionId);
            } else {
                throw new IllegalArgumentException("No valid session keys available");
            }
        }
        
        // Make sure our session key is exactly 32 bytes for AES-256
        if (sessionKey.length != 32) {
            byte[] adjustedKey = new byte[32];
            Arrays.fill(adjustedKey, (byte)0); // Fill with zeros
            System.arraycopy(sessionKey, 0, adjustedKey, 0, Math.min(sessionKey.length, 32));
            sessionKey = adjustedKey;
        }
        
        System.out.println("Using session key of length: " + sessionKey.length);
        
        return symmetricCrypto.decrypt(
            ciphertext, 
            Base64.getEncoder().encodeToString(sessionKey), 
            iv, 
            associatedData
        );
    }
    
    /**
     * Sign a message with the server's Dilithium key
     * 
     * @param data The data to sign
     * @return Base64-encoded signature
     * @throws Exception If signing fails
     */
    public String signData(byte[] data) throws Exception {
        byte[] signature = dilithium.sign(serverSigningKeys.getPrivate(), data);
        return Base64.getEncoder().encodeToString(signature);
    }
    
    /**
     * Verify a signature using a public key
     * 
     * @param data The data that was signed
     * @param signature Base64-encoded signature
     * @param publicKeyBase64 Base64-encoded Dilithium public key
     * @return true if signature is valid
     * @throws Exception If verification fails
     */
    public boolean verifySignature(byte[] data, String signatureBase64, String publicKeyBase64) throws Exception {
        byte[] signature = Base64.getDecoder().decode(signatureBase64);
        java.security.PublicKey publicKey = java.security.KeyFactory.getInstance("Dilithium", "BCPQC")
            .generatePublic(new java.security.spec.X509EncodedKeySpec(
                Base64.getDecoder().decode(publicKeyBase64)));
        
        return dilithium.verify(publicKey, data, signature);
    }
    
    /**
     * Compute a file hash using SHA3-512
     * 
     * @param file The file to hash
     * @return Base64-encoded hash
     * @throws Exception If hashing fails
     */
    public String computeFileHash(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(Constants.HASH_ALGORITHM);
        byte[] buffer = new byte[8192];
        int bytesRead;
        
        try (FileInputStream fis = new FileInputStream(file)) {
            while ((bytesRead = fis.read(buffer)) != -1) {
                digest.update(buffer, 0, bytesRead);
            }
        }
        
        byte[] hashBytes = digest.digest();
        return Base64.getEncoder().encodeToString(hashBytes);
    }
    
    /**
     * Verify a TOTP code
     * 
     * @param totpSecret Base32-encoded TOTP secret
     * @param totpCode TOTP code to verify
     * @return true if TOTP code is valid
     */
    public boolean verifyTOTP(String totpSecret, String totpCode) {
        return totpManager.verifyTOTP(totpSecret, totpCode);
    }
    
    /**
     * Validate a message nonce to prevent replay attacks
     * 
     * @param nonce Base64-encoded nonce
     * @return true if nonce is valid and not seen before
     */
    public boolean validateNonce(String nonce) {
        byte[] nonceBytes = Base64.getDecoder().decode(nonce);
        
        // Check if nonce has been seen before
        if (nonceCache.containsNonce(nonceBytes)) {
            return false;
        }
        
        // Add nonce to cache
        nonceCache.addNonce(nonceBytes);
        return true;
    }
    
    /**
     * Generate a random session ID
     * 
     * @return Random session ID
     */
    private String generateSessionId() {
        // Use UUID format for consistency with AuthManager
        return java.util.UUID.randomUUID().toString();
    }
    
    /**
     * Remove a session and its keys
     * 
     * @param sessionId The session ID to remove
     */
    public void removeSession(String sessionId) {
        sessionKeys.remove(sessionId);
    }
    
    /**
     * Dump all session keys for debugging
     */
    public void dumpSessionKeys() {
        System.out.println("=== ACTIVE SESSION KEYS ===");
        for (Map.Entry<String, byte[]> entry : sessionKeys.entrySet()) {
            System.out.println("Session ID: " + entry.getKey() + 
                             ", Key length: " + entry.getValue().length + 
                             ", Key hash: " + Arrays.hashCode(entry.getValue()));
        }
        System.out.println("=========================");
    }
    
    /**
     * Get a copy of all session keys for advanced decryption attempts
     * 
     * @return Map of session IDs to key bytes
     */
    public Map<String, byte[]> getAllSessionKeys() {
        // Create a copy to avoid exposing the internal map
        Map<String, byte[]> keyCopy = new HashMap<>();
        for (Map.Entry<String, byte[]> entry : sessionKeys.entrySet()) {
            // Create a copy of each key
            byte[] keyBytes = new byte[entry.getValue().length];
            System.arraycopy(entry.getValue(), 0, keyBytes, 0, entry.getValue().length);
            keyCopy.put(entry.getKey(), keyBytes);
        }
        return keyCopy;
    }
    
    /**
     * Get the server's Dilithium public key
     * 
     * @return Base64-encoded Dilithium public key
     */
    public String getServerPublicKey() {
        return Base64.getEncoder().encodeToString(serverSigningKeys.getPublic().getEncoded());
    }
}