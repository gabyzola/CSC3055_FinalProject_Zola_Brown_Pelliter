package pqcrypto;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;

import java.security.*;

import javax.crypto.SecretKey;

import java.util.HashMap;
import java.util.Map;

import merrimackutil.util.NonceCache;

import common.Config; 

/**
 * coordinates cryptographic operations across the system
 */
public class CryptoManager {

    // core crypto components 
    private final KyberOperations kyberOps;
    private final DilithiumOperations dilithiumOps;
    private final SymmetricCrypto symCrypto;

    // nonce cache for replay attack prevention
    private final NonceCache nonceCache;

    // session management 
    private final Map<String, SecretKey> sessionKeys;

    // key pairs
    private KeyPair kyberKeyPair;
    private KeyPair dilithiumKeyPair; 

    // configuration 
    private final Config config; 

    public CryptoManager(Config config) throws GeneralSecurityException {
        System.out.println("(CryptoManager.java) initializing constructor...");
        this.config = config; 

        // initialize crypto components
        this.kyberOps = new KyberOperations();
        this.dilithiumOps = new DilithiumOperations();
        this.symCrypto = new SymmetricCrypto();

        System.out.println("(CryptoManager.java) creating nonce cache...");
        // create nonce cache with config parameters
        this.nonceCache = new NonceCache(this.config.getInt("protocol.nonce_size_bytes", 16), config.getInt("security.session_key_lifetime_mins", 60) * 60);

        // initalize session storage
        this.sessionKeys = new HashMap<>();

        System.out.println("(CryptoManager.java) generating...");
        generateKeyPairs();

        System.out.println("(CryptoManager.java) all good, initialization complete");
    }

    /**
     * generates Kyber and Dilithium key pairs 
     * @throws GeneralSecurityException
     */
    private void generateKeyPairs() throws GeneralSecurityException {
        System.out.println("(CryptoManger.java) generating key pairs----------------");

        // generate kyber pairs for key exchange 
        this.kyberKeyPair = kyberOps.generateKeyPair();
        System.out.println("(CryptoManger.java) kyber key pair generated");
        
        // generate dilithium for signatures
        this.dilithiumKeyPair = dilithiumOps.generateKeyPair();
        System.out.println("(CryptoManger.java) dilithium key pair generated");
    }

    /**
     * returns the kyber public key for this instance
     * @return
     */
    public PublicKey getKyberPublicKey() {
        System.out.println("(CryptoManger.java) returning kyber public key");
        return kyberKeyPair.getPublic();
    }

    /**
     * retunrs the dilithium public key
     * @return
     */
    public PublicKey getDilithiumPublicKey() {
        System.out.println("(CryptoManger.java : pq) rerturning Dilithium public key");
        return dilithiumKeyPair.getPublic();
    }

    /**
     * performs key encapsulation for establishing a secure session
     * @param sessionId
     * @param recipientPublicKey
     * @return
     * @throws GeneralSecurityException
     */
    public byte[] establishSession(String sessionId, PublicKey recipientPublicKey) throws GeneralSecurityException {
        System.out.println("(CryptoManger.java: pq) establishing session: " + sessionId);

        try {

            // get secret key and its encapsulation
            SecretKeyWithEncapsulation keyWithEncap = kyberOps.encapsulateWithSecret(recipientPublicKey);

            // store the session key 
            sessionKeys.put(sessionId, keyWithEncap);

            System.out.println("CryptoMng (pq): session established");
            // return just the encapsulation to send to the recipient 
            return keyWithEncap.getEncapsulation();
        } catch (Exception e) {
            System.out.println("(CryptoManger.java: pq) ERROR session establishment failed: " +e.getMessage());
            throw new GeneralSecurityException("Failed to establish session", e);
        }
    }

    /**
     * completes session establishment by decapsulating a received key
     * @param sessionId
     * @param encapsulatedKey
     * @throws GeneralSecurityException
     */
    public void completeSession(String sessionId, byte[] encapsulatedKey) throws GeneralSecurityException {
        System.out.println("CryptoMng: pq: completing session: " + sessionId);

        try {

            // decapsulate to get the shared secret 
            byte[] sharedSecret = kyberOps.decapsulate(kyberKeyPair.getPrivate(), encapsulatedKey);

            // create a secret key from the shared secret 
            SecretKey sessionKey = symCrypto.convertBytesToKey(sharedSecret);

            // store the session key
            sessionKeys.put(sessionId, sessionKey);
            System.out.println("CryptoMng: pq: session completed successfully");
        } catch (Exception e) {
            System.out.println("CryptoMng: pq: ERROR: session completion failed: " + e.getMessage());
            throw new GeneralSecurityException("Failed to complete session", e);
        }
    }

    /**
     * signs data using the instance's Dilithium private key
     * @param data
     * @return
     * @throws GeneralSecurityException
     */
    public byte[] sign(byte[] data) throws GeneralSecurityException {
        System.out.println("CryptoMng: pq: signing data");
        return dilithiumOps.sign(dilithiumKeyPair.getPrivate(), data);
    }

    /**
     * verifies a signature using the specifiied public key
     * @param data
     * @param signature
     * @param publicKey
     * @return
     * @throws GeneralSecurityException
     */
    public boolean verify(byte[] data, byte[] signature, PublicKey publicKey) throws GeneralSecurityException {
        System.out.println("CryptoMng: pq: verifying signature");
        return dilithiumOps.verify(publicKey, data, signature);
    }

    /**
     * encrypts data using the session key for the specified session
     * @param sessionId
     * @param data
     * @param associatedData
     * @return
     * @throws GeneralSecurityException
     */
    public byte[] encrypt(String sessionId, byte[] data, byte[] associatedData) throws GeneralSecurityException {
        System.out.println("CryptoMng: pq: encrypting data for session: " + sessionId);

        SecretKey sessionKey = sessionKeys.get(sessionId);
        if (sessionKey == null) {
            throw new GeneralSecurityException("Session key not found for ID: " + sessionId);
        }

        try {
            System.out.println("CryptoMng: pq: encrypting and returning...");
            return symCrypto.encrypt(data, sessionKey, associatedData);
        } catch (Exception e) {
            System.out.println("CryptoMng: pq: ERRO: encryption failed");
            throw new GeneralSecurityException("Encryption failed", e);
        }
    }

    /**
     * encrypts a file using a new random key (every file encryptoo uses a unique key)
     * @param fileData
     * @param associatedData
     * @return
     * @throws GeneralSecurityException
     */
    public FileEncryptionResult encryptFile(byte[] fileData, byte[] associatedData) throws GeneralSecurityException {
        System.out.println("CryptMng: pq: encrypting file");

        try {
            
            // generate random key for this file
            SecretKey fileKey = symCrypto.generateKey();

            // encrypt the file data
            byte[] encryptedData = symCrypto.encrypt(fileData, fileKey, associatedData);

            // return both the encrypted file and the key
            return new FileEncryptionResult(encryptedData, fileKey);
 
       } catch (Exception e) {
            throw new GeneralSecurityException("File encryption failed", e);
       }
    }

    /**
     * decrypts data using the session key for the specified session
     * @param sessionId
     * @param encryptedData
     * @param associatedData
     * @return
     * @throws GeneralSecurityException
     */
    public byte[] decrypt(String sessionId, byte[] encryptedData, byte[] associatedData) throws GeneralSecurityException {
        System.out.println("CryptoMng: pq: decrypting for session: " + sessionId);

        SecretKey sessionKey = sessionKeys.get(sessionId);
        if (sessionKey == null) {
            throw new GeneralSecurityException("ERROR: CryptoMng: pq: session key not found for ID: " + sessionId);
        }

        try {
            System.out.println("CryptoMng: pq: decrypting and returning");
            return symCrypto.decrypt(encryptedData, sessionKey, associatedData);
        } catch (Exception e) {
            throw new GeneralSecurityException("ERROR: decryption failed", e);
        }
    }

    /**
     * decrypts a file using the provided file key
     * @param encryptedFile
     * @param fileKey
     * @param associatedData
     * @return
     * @throws GeneralSecurityException
     */
    public byte[] decryptFile(byte[] encryptedFile, SecretKey fileKey, byte[] associatedData) throws GeneralSecurityException {
        System.out.println("CryptoMng: pq: decrypting file");

        try {
            return symCrypto.decrypt(encryptedFile, fileKey, associatedData);
        } catch (Exception e) {
            throw new GeneralSecurityException("CryptoMng: pq: ERROR: file decryption failed", e);
        }
    }

    /**
     * generates a fresh nonce for use in protocol messages
     * @return
     */
    public byte[] generateNonce() {
        System.out.println("CryptoMng: pq: generating fresh nonce");
        return nonceCache.getNonce();
    }

    /**
     * validates a received nonce to prevent replay attacks
     * @param nonce
     * @return
     */
    public boolean validateNonce(byte[] nonce) {
        System.out.println("CryptoMng: pq: validating nonce");

        if (nonceCache.containsNonce(nonce)) {
            System.out.println("CryptoMng: pq: nonce validation failed: already used");
            return false;
        }

        // add nonce to cache to prevent re-use
        nonceCache.addNonce(nonce);
        System.out.println("CryptoMng: pq: nonce is valid");
        return true; 
    }

    /**
     * closes a session, removing its key from memory
     * @param sessionId
     */
    public void closeSession(String sessionId) {
        System.out.println("CryptoMng: pq: closing session: " + sessionId);
        sessionKeys.remove(sessionId);
    }

    /**
     * converts raw byte[] into a SecureKey object
     * @param keyBytes
     * @return
     */
    public SecretKey convertBytesToKey(byte[] keyBytes) {
        System.out.println("CryptoMng: converting byte array to SecretKey");
        return symCrypto.convertBytesToKey(keyBytes);
    }

}
