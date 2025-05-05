package pqcrypto;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import common.Config;
import common.Constants;
import common.Message;
import common.User;

import merrimackutil.json.JsonIO;
import merrimackutil.json.types.JSONObject;
import merrimackutil.json.types.JSONArray;

/**
 * authentication and session manager for the system
 * handes user authentication, session creation, TOTP verification, and session security
 */
public class AuthManager {
    
    private final Config config;
    private final CryptoManager cryptoManager;
    private final TOTPManager totpManager;

    private final Map<String, User> users;
    private final String userStorageFile;
    private final Map<String, SessionInfo> activeSessions;

    public AuthManager(Config config, CryptoManager cryptoManager) throws IOException {
        this.config = config;
        this.cryptoManager = cryptoManager;
        this.totpManager = new TOTPManager();

        this.userStorageFile = config.getString("storage.keystore_path", "./stores/users.json");
        this.users = new HashMap<>();
        this.activeSessions = new HashMap<>();

        loadUsers();

        System.out.println("AuthManager: Initiated with " + users.size() + " users");   
    }

    /**
     * load users from storage file
     * @throws IOException
     */
    private void loadUsers() throws IOException {
        File file = new File(this.userStorageFile);
        if (!file.exists()) {
            createDefaultAdmin();
            saveUsers();
            return;
        }

        try {
            JSONObject root = JsonIO.readObject(file);
            JSONArray userArray = root.getArray("users");

            if (userArray != null) {
                for (int i = 0; i < userArray.size(); i++) {
                    JSONObject userObj = userArray.getObject(i);
                    try {
                        User user = new User(userObj);
                        users.put(user.getUsername(), user);
                    } catch (Exception e) {
                        System.err.println("AuthManager: ERROR: Failed to load user: " + e.getMessage());
                    }
                }
            }
        } catch (FileNotFoundException e) {
            throw new IOException("AuthManager: ERROR: user file exists but can't be read", e);
        }
    }

    /**
     * saves users to storage file
     * @throws IOException
     */
    private void saveUsers() throws IOException {
        JSONObject root = new JSONObject();
        JSONArray userArray = new JSONArray();

        for (User user : users.values()) {
            userArray.add(user.toJSONType());
        }
        root.put("users", userArray);

        // create new parent directory if it doesnt exist 
        File file = new File(userStorageFile);
        file.getParentFile().mkdirs();

        // write file atomically
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(root.toJSON());
        }
    }

    /**
     * creates a default admin user
     */
    private void createDefaultAdmin() {
        try {
            User admin = new User("admin", "admin123");
            admin.setTotpSecret(totpManager.generateSecret());
            admin.setRole("admin");
            users.put("admin", admin);

            System.out.println("AuthManager: Created default admin user");
            System.out.println("AuthManager: TOTP Secret: " + admin.getTotpSecret());
            System.out.println("AuthManager: Configure you authenticator app with this secret");
        } catch (Exception e) {
            System.err.println("AuthManager: failed to create default admin: " + e.getMessage());
        }
    }

    /**
     * creates a new user account
     * @param username
     * @param password
     * @param role
     * @return
     * @throws IOException
     */
    public String createUser(String username, String password, String role) throws IOException {
        if (users.containsKey(username)) {
            throw new IllegalArgumentException("AuthManager: username already exists");
        }

        try {
            User user = new User(username, password);
            String totpSecret = totpManager.generateSecret();
            user.setTotpSecret(totpSecret);
            user.setRole(role);

            users.put(username, user);
            saveUsers();

            return totpSecret;
        } catch (Exception e) {
            throw new IOException("AuthManager: ERROR: failed to create user", e);
        }
    }

    public Message handleLoginRequest(Message message) {
        String username = message.getPayloadString(Constants.FIELD_USERNAME);
        String password = message.getPayloadString(Constants.FIELD_PASSWORD);

        if (username == null || password == null) {
            return message.createErrorResponse(Constants.ERROR_AUTHENTICATION_FALED, "AuthManager: ERROR: Username and password required");
        }

        User user = users.get(username);
        if (user == null || !user.isActive()) {
            return message.createErrorResponse(Constants.ERROR_AUTHENTICATION_FALED, "AuthManager: ERROR: Invalid username or password (user not active)");
        }

        try {

            if (!user.verifyPassword(password)) {
                return message.createErrorResponse(Constants.ERROR_AUTHENTICATION_FALED, "AuthManager: ERROR: invalid username or password (password verification)");
            }

            // create new session
            String sessionId = UUID.randomUUID().toString();
            int sessionTimeout = config.getInt("server.session_timeout_mins", 30);
            activeSessions.put(sessionId, new SessionInfo(username, sessionTimeout));

            // create totp challenge 
            Message response = message.createResponse(Constants.MSG_TYPE_TOTP_CHALLENGE);
            response.setSessionId(sessionId);
            response.setNonce(cryptoManager.generateNonce());

            return response;
        } catch (Exception e) {
            return message.createErrorResponse(Constants.ERROR_AUTHENTICATION_FALED, "AuthManager: ERROR: authentication failed: " + e.getMessage());
        }
    }

    /**
     * handles a TOTP verificatino response
     * @param message
     * @return
     */
    public Message handleTotpResponse(Message message) {
        String sessionId = message.getSessionId();
        String totpCode = message.getPayloadString(Constants.FIELD_TOTP_CODE);

        if (sessionId == null || !activeSessions.containsKey(sessionId)) {
            return message.createErrorResponse(Constants.ERROR_SESSION_EXPIRED, "AuthManager: ERROR: Invalid or expired session");
        }

        SessionInfo session = activeSessions.get(sessionId);
        if (session.isExpired()) {
            activeSessions.remove(sessionId);
            return message.createErrorResponse(Constants.ERROR_SESSION_EXPIRED, "AuthManager: ERROR: session expired");
        }

        if (totpCode == null) {
            return message.createErrorResponse(Constants.ERROR_TOTP_INVALID, "AuthManager: ERROR: totp code required");
        }

        User user = users.get(session.username);
        if (user == null || !user.isActive()) {
            activeSessions.remove(sessionId);
            return message.createErrorResponse(Constants.ERROR_AUTHENTICATION_FALED, "AuthManager: ERROR: User is not longer active)");
        }

        if (!totpManager.verifyCode(user.getTotpSecret(), totpCode)) {
            return message.createErrorResponse(Constants.ERROR_TOTP_INVALID, "AuthManager: ERROR: invalid totp code");
        }

        // totp verified, mark session as fully authenticated
        session.totpVerified = true;

        // create key exhange responses
        Message response = message.createResponse(Constants.MSG_TYPE_KEY_EXCHANGE);
        response.setNonce(cryptoManager.generateNonce());

        // include kyber publicn key for key exchange
        try {
            PublicKey kyberPublicKey = cryptoManager.getKyberPublicKey();
            byte[] keyBytes = kyberPublicKey.getEncoded();
            response.addPayload("kyber_public_kry", keyBytes);
        } catch (Exception e) {
            return message.createErrorResponse(Constants.ERROR_SERVER_INTERNAL, "AuthManager: ERROR: failed to generate key exchange: " + e.getMessage());
        }
        return response;
    }

    /**
     * completes the key exchange and session establishment 
     * @param message
     * @return
     */
    public Message completeKeyExchange(Message message) {
        String sessionId = message.getSessionId();

        if (sessionId == null ||!activeSessions.containsKey(sessionId)) {
            return message.createErrorResponse(Constants.ERROR_SESSION_EXPIRED, "AuthManager: ERROR: invalid or expired session");
        }

        SessionInfo session = activeSessions.get(sessionId);
        if (session.isExpired()) {
            activeSessions.remove(sessionId);
            return message.createErrorResponse(Constants.ERROR_SESSION_EXPIRED, "AuthManager: ERROR: session expired");
        }

        if (!session.totpVerified) {
            return message.createErrorResponse(Constants.ERROR_AUTHENTICATION_FALED, "AuthManager: ERROR: totp verification required before key exchange");
        }

        byte[] encapsulatedKey = message.getPayloadBytes("encapsulated_key");
        if (encapsulatedKey == null) {
            return message.createErrorResponse(Constants.ERROR_AUTHENTICATION_FALED, "AuthManager: ERROR: missing encapsulated key");
        }

        try {
            // complete the session with the encapsulated key
            cryptoManager.completeSession(sessionId, encapsulatedKey);

            // create success response
            Message response = message.createResponse("AUTH_SUCCESS");
            response.setNonce(cryptoManager.generateNonce());

            // sign the response
            byte[] dataToSign = response.getDataToSign();
            byte[] signature = cryptoManager.sign(dataToSign);
            response.setSignature(signature);

            return response;
        } catch (GeneralSecurityException e) {
            return message.createErrorResponse(Constants.ERROR_SERVER_INTERNAL, "AuthManager: ERROR: failed to complete key exchange: " + e.getMessage());
        }
    }

    /**
     * validates if a session is active and authenticated 
     * @param sessionId
     * @return
     */
    public boolean isSessionValid(String sessionId) {
        if (sessionId == null || !activeSessions.containsKey(sessionId)) {
            return false;
        }

        SessionInfo session = activeSessions.get(sessionId);
        if (session.isExpired()) {
            activeSessions.remove(sessionId);
            return false; 
        }

        return session.totpVerified;
    }

    /**
     * gets the usernname associated with a session
     * @param sessionId
     * @return
     */
    public String getUsernameForSession(String sessionId) {
        if (!isSessionValid(sessionId)) {
            System.out.println("AuthManager: getUsernameForSession -> null");
            return null;
        }

        return activeSessions.get(sessionId).username;
    }

    /**
     * gets a user by username
     * @param username
     * @return
     */
    public User getUser(String username) {
        return users.get(username);
    }
    
    /**
     * closes a session
     * @param sessionId
     */
    public void closeSession(String sessionId) {
        if (sessionId != null && activeSessions.containsKey(sessionId)) {
            activeSessions.remove(sessionId);
            cryptoManager.closeSession(sessionId);
            System.out.println("AuthManager: closed sessin " + sessionId);
        }
    }

    /**
     * generates a TOTP uri for user's authenticator app 
     * @param usernaem
     * @return
     */
    public String generateTotpUri(String username) {
        User user = users.get(username);
        if (user == null) {
            System.out.println("AuthManager: generateTotpUri -> null");
            return null;
        }

        String issuer = config.getString("server.totp_issuer", "PQBlockchainFileShare");
        return totpManager.generateTotpUri(issuer, username, user.getTotpSecret());
    }

    /**
     * cleans up expired sessions
     */
    public void cleanupExpiredSessions() {
        long now = Instant.now().getEpochSecond();

        activeSessions.entrySet().removeIf(entry -> {
            SessionInfo session = entry.getValue();
            if (now < session.expiryTime) {
                cryptoManager.closeSession(entry.getKey());
                return true;
            }
            return false;
        });
    }
}
