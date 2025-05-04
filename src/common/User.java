package common;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import merrimackutil.json.JSONSerializable;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONType;

import java.io.InvalidObjectException;

/**
 * represents a user within the system
 * stores credentials, authentication data, password verification and TOTP secret management
 */
public class User implements JSONSerializable {
    
    // core user information
    private String username;
    private String passwordHash;
    private String salt; 
    private String totpSecret;

    // optional public keys for cryptographic operations
    private byte[] kyberPublicKey;
    private byte[] dilithiumPublicKey;

    // user status and permissions
    private boolean isActive;
    private String role;

    /**
     * constructor, 
     * automatically hashes the password and generates a TOTP secret 
     * @param username
     * @param password
     * @throws NoSuchAlgorithmException
     */
    public User(String username, String password) throws NoSuchAlgorithmException {
        this.username = username;
        this.salt = generateSalt();
        this.passwordHash = hashPassword(password, salt);
        this.totpSecret = generateTotpSecret();
        this.isActive = true;
        this.role = "user"; // default role
    }

    /**
     * creates a user from JSON data (used for deserialization)
     * @param obj
     * @throws InvalidObjectException
     */
    public User(JSONObject obj) throws InvalidObjectException {
        deserialize(obj);
    }

    /**
     * gets the username
     * @return
     */
    public String getUsername() {
        return this.username; 
    }

    /**
     * gets the TOTP secret for this user
     * @return
     */
    public String getTotpSecret() {
        return this.totpSecret;
    }

    /**
     * sets new TOTP secret for this user
     * @param totpSecret
     */
    public void setTotpSecret(String totpSecret) {
        this.totpSecret = totpSecret;
    }

    /**
     * checks if the provided password matches the stored hash
     * @param candidatePassword
     * @return
     * @throws NoSuchAlgorithmException
     */
    public boolean verifyPassword(String candidatePassword) throws NoSuchAlgorithmException {
        String candidateHash = hashPassword(candidatePassword, this.salt);
        return candidateHash.equals(this.passwordHash);
    }

    /**
     * sets a new password
     * @param newPassword
     * @throws NoSuchAlgorithmException
     */
    public void setPassword(String newPassword) throws NoSuchAlgorithmException {
        this.salt = generateSalt();
        this.passwordHash = hashPassword(newPassword, salt);
    }

    /**
     * gets the kyber public key
     * @return
     */
    public byte[] getKyberPublicKey() {
        return this.kyberPublicKey;
    }

    /**
     * sets the kyber public key
     * @param kyberPublicKey
     */
    public void setKyberPublicKey(byte[] kyberPublicKey) {
        this.kyberPublicKey = kyberPublicKey;
    }

    /**
     * get the dilithium public ket
     * @return
     */
    public byte[] getDilithiumPublicKey() {
        return this.dilithiumPublicKey;
    }

    /**
     * sets the dilithium public key
     * @param dilithiumPublicKey
     */
    public void setDilithiumPublicKey(byte[] dilithiumPublicKey) {
        this.dilithiumPublicKey = dilithiumPublicKey;
    }

    /**
     * checks if the user account is active
     * @return
     */
    public boolean isActive() {
        return this.isActive;
    }

    /**
     * gets the users role
     * @return
     */
    public String getRole() {
        return this.role;
    }

    /**
     * sets the users role
     * @param role
     */
    public void setRole(String role) {
        this.role = role; 
    }

    /**
     * hashes the password with the provided salt using SHA3-512
     * @param password
     * @param salt
     * @return the hashed password as a b64 encoded string
     * @throws NoSuchAlgorithmException
     */
    private String hashPassword(String password, String salt) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA3-512");
        md.update(salt.getBytes());
        byte[] hash = md.digest(password.getBytes());
        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * generates a random salt for password hashing
     * @return
     */
    private String generateSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        return Base64.getEncoder().encodeToString(salt);
    }

    /**
     * generates a random TOTP secret 
     * @return
     */
    private String generateTotpSecret() {
        SecureRandom random = new SecureRandom();
        byte[] secret = new byte[20]; 
        random.nextBytes(secret);

        return Base64.getEncoder().encodeToString(secret);
    }

    /**
     * converts the user object to a JSON type for serialization
     */
    @Override
    public JSONType toJSONType() {
        JSONObject obj = new JSONObject();

        obj.put("username", this.username);
        obj.put("password-hash", this.passwordHash);
        obj.put("salt", this.salt);
        obj.put("totp0secret", this.totpSecret);
        obj.put("active", this.isActive);
        obj.put("role", this.role);

        // only include keys if theu exist
        if (this.kyberPublicKey != null) {
            obj.put("kyber-public-key", Base64.getEncoder().encodeToString(this.kyberPublicKey));
        }
        if (this.dilithiumPublicKey != null) {
            obj.put("dilithium-public-key", Base64.getEncoder().encodeToString(this.dilithiumPublicKey));
        }
        return obj;
    }

    /**
     * serializes this user object to a JSON string
     */
    @Override
    public String serialize() {
        return toJSONType().toJSON();
    }

    /**
     * deserializes a JSONObject into this user object
     */
    @Override
    public void deserialize(JSONType obj) throws InvalidObjectException {
        if (obj instanceof Object) {
            JSONObject userObj = (JSONObject) obj;

            // required fields
            this.username = userObj.getString("username");
            this.passwordHash = userObj.getString("password-hash");
            this.salt = userObj.getString("salt");
            this.totpSecret = userObj.getString("totp-secret");

            // optional fields with defaults
            this.isActive = userObj.getBoolean("active") != null ? userObj.getBoolean("active") : true;
            this.role = userObj.getString("role") != null ? userObj.getString("role") : "user";

            // public keys 
            String kyberKey = userObj.getString("kyber-public-key");
            if (kyberKey != null) {
                this.kyberPublicKey = Base64.getDecoder().decode(kyberKey);
            }

            String dilithiumKey = userObj.getString("dilithium-public-key");
            if (dilithiumKey != null) {
                this.dilithiumPublicKey = Base64.getDecoder().decode(dilithiumKey);
            }
        } else {
            throw new InvalidObjectException("User: ERROR: Expected JSON Object for User deserialiation");
        }
    }
}
