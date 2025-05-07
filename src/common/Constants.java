package common;

/**
 * System-wide constant values used across the application.
 */
public class Constants {
    // Protocol version
    public static final String PROTOCOL_VERSION = "1.0";
    
    // Message types
    public static final String MSG_TYPE_HELLO = "HELLO";
    public static final String MSG_TYPE_AUTH_REQUEST = "AUTH_REQUEST";
    public static final String MSG_TYPE_AUTH_RESPONSE = "AUTH_RESPONSE";
    public static final String MSG_TYPE_SESSION_KEY = "SESSION_KEY";
    public static final String MSG_TYPE_UPLOAD_REQUEST = "UPLOAD_REQUEST";
    public static final String MSG_TYPE_UPLOAD_RESPONSE = "UPLOAD_RESPONSE";
    public static final String MSG_TYPE_DOWNLOAD_REQUEST = "DOWNLOAD_REQUEST";
    public static final String MSG_TYPE_DOWNLOAD_RESPONSE = "DOWNLOAD_RESPONSE";
    public static final String MSG_TYPE_LIST_REQUEST = "LIST_REQUEST";
    public static final String MSG_TYPE_LIST_RESPONSE = "LIST_RESPONSE";
    public static final String MSG_TYPE_BLOCKCHAIN_REQUEST = "BLOCKCHAIN_REQUEST";
    public static final String MSG_TYPE_BLOCKCHAIN_RESPONSE = "BLOCKCHAIN_RESPONSE";
    public static final String MSG_TYPE_VERIFY_REQUEST = "VERIFY_REQUEST";
    public static final String MSG_TYPE_VERIFY_RESPONSE = "VERIFY_RESPONSE";
    public static final String MSG_TYPE_ERROR = "ERROR";
    public static final String MSG_TYPE_GOODBYE = "GOODBYE";

    // Error codes
    public static final int ERROR_AUTHENTICATION_FAILED = 1001;
    public static final int ERROR_INVALID_MESSAGE = 1002;
    public static final int ERROR_FILE_NOT_FOUND = 1003;
    public static final int ERROR_PERMISSION_DENIED = 1004;
    public static final int ERROR_BLOCKCHAIN_VERIFICATION = 1005;
    public static final int ERROR_INTERNAL_SERVER = 1006;
    public static final int ERROR_INVALID_FILE = 1007;
    public static final int ERROR_MAX_FILE_SIZE = 1008;
    
    // Cryptographic parameters
    public static final String AES_MODE = "AES/GCM/NoPadding";
    public static final int AES_KEY_SIZE = 256;
    public static final int AES_GCM_TAG_LENGTH = 128;
    public static final int NONCE_SIZE = 16;
    public static final String HASH_ALGORITHM = "SHA3-512";
    public static final int TOTP_WINDOW_SIZE = 1; // Allow 1 step before/after
    public static final int TOTP_PERIOD = 30; // 30 seconds
    public static final int TOTP_DIGITS = 6;
    
    // Blockchain parameters
    public static final int BLOCK_SIZE_LIMIT = 10; // Transactions per block
    public static final String GENESIS_BLOCK_HASH = "0000000000000000000000000000000000000000000000000000000000000000";
    
    // Network parameters
    public static final int DEFAULT_SERVER_PORT = 5001;
    public static final int SOCKET_TIMEOUT = 30000; // 30 seconds
    
    // File parameters
    public static final long MAX_FILE_SIZE = 10 * 1024 * 1024; // 10 MB
}