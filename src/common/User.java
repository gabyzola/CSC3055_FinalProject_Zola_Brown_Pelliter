package common;

import java.io.InvalidObjectException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

/**
 * Represents a user in the system with authentication details.
 */
public class User implements JSONSerializable {
    private String username;
    private String passwordHash;
    private String passwordSalt;
    private String totpSecret;
    private String kyberPublicKey;
    private String dilithiumPublicKey;
    
    /**
     * Create a new user from JSON
     * 
     * @param obj JSONObject containing user data
     * @throws InvalidObjectException If JSON structure is invalid
     */
    public User(JSONObject obj) throws InvalidObjectException {
        deserialize(obj);
    }
    
    /**
     * Create a new user with the given details
     * 
     * @param username The username
     * @param password The plaintext password
     * @throws NoSuchAlgorithmException If SHA-512 is not available
     */
    public User(String username, String password) throws NoSuchAlgorithmException {
        this.username = username;
        this.passwordSalt = generateSalt();
        this.passwordHash = hashPassword(password, this.passwordSalt);
        this.totpSecret = generateTotpSecret();
    }
    
    /**
     * Get the username
     * 
     * @return The username
     */
    public String getUsername() {
        return username;
    }
    
    /**
     * Get the TOTP secret
     * 
     * @return Base32 encoded TOTP secret
     */
    public String getTotpSecret() {
        return totpSecret;
    }
    
    /**
     * Get the Kyber public key
     * 
     * @return Base64 encoded Kyber public key
     */
    public String getKyberPublicKey() {
        return kyberPublicKey;
    }
    
    /**
     * Set the Kyber public key
     * 
     * @param kyberPublicKey Base64 encoded Kyber public key
     */
    public void setKyberPublicKey(String kyberPublicKey) {
        this.kyberPublicKey = kyberPublicKey;
    }
    
    /**
     * Get the Dilithium public key
     * 
     * @return Base64 encoded Dilithium public key
     */
    public String getDilithiumPublicKey() {
        return dilithiumPublicKey;
    }
    
    /**
     * Set the Dilithium public key
     * 
     * @param dilithiumPublicKey Base64 encoded Dilithium public key
     */
    public void setDilithiumPublicKey(String dilithiumPublicKey) {
        this.dilithiumPublicKey = dilithiumPublicKey;
    }
    
    /**
     * Verify a password against the stored hash
     * 
     * @param password The password to verify
     * @return True if password matches
     * @throws NoSuchAlgorithmException If SHA-512 is not available
     */
    public boolean verifyPassword(String password) throws NoSuchAlgorithmException {
        String hash = hashPassword(password, this.passwordSalt);
        return hash.equals(this.passwordHash);
    }
    
    /**
     * Generate a random salt for password hashing
     * 
     * @return Base64 encoded salt
     */
    private String generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }
    
    /**
     * Hash a password with the given salt using SHA-512
     * 
     * @param password The password to hash
     * @param salt The salt to use
     * @return Base64 encoded hash
     * @throws NoSuchAlgorithmException If SHA-512 is not available
     */
    private String hashPassword(String password, String salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-512");
        md.update(Base64.getDecoder().decode(salt));
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }
    
    /**
     * Generate a random TOTP secret
     * 
     * @return Base32 encoded TOTP secret
     */
    private String generateTotpSecret() {
        byte[] secret = new byte[20];
        new SecureRandom().nextBytes(secret);
        return merrimackutil.codec.Base32.encodeToString(secret, false);
    }
    
    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (!(obj instanceof JSONObject)) {
            throw new InvalidObjectException("Expected JSONObject for User");
        }
        
        JSONObject user = (JSONObject) obj;
        
        // Validate required fields
        String[] requiredFields = {"username", "passwordHash", "passwordSalt", "totpSecret"};
        for (String field : requiredFields) {
            if (!user.containsKey(field) || user.getString(field) == null) {
                throw new InvalidObjectException("Missing required field: " + field);
            }
        }
        
        this.username = user.getString("username");
        this.passwordHash = user.getString("passwordHash");
        this.passwordSalt = user.getString("passwordSalt");
        this.totpSecret = user.getString("totpSecret");
        
        // Optional fields
        this.kyberPublicKey = user.getString("kyberPublicKey");
        this.dilithiumPublicKey = user.getString("dilithiumPublicKey");
    }

    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();
        obj.put("username", username);
        obj.put("passwordHash", passwordHash);
        obj.put("passwordSalt", passwordSalt);
        obj.put("totpSecret", totpSecret);
        
        if (kyberPublicKey != null) {
            obj.put("kyberPublicKey", kyberPublicKey);
        }
        
        if (dilithiumPublicKey != null) {
            obj.put("dilithiumPublicKey", dilithiumPublicKey);
        }
        
        return obj;
    }
    
    @Override
    public String serialize() {
        return toJSONType().toJSON();
    }

}