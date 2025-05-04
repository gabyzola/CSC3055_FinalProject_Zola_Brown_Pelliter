package common;

/**
 * system wide constants for the PQ Blockchain file sharing system (PBFS-Peanut Butter Fibonnaci Sequence) 
 */
public class Constants {
    
    /**
     * protocol version and identifiers, used to ensure client and server are compatible 
     */
    public static final String PROTOCOL_VERSION = "1.0";
    public static final int PROTOCOL_MAJOR_VERSION = 1;
    public static final int PROTOCOL_MINOR_VERSION = 0; 

    /**
     * message types for client serve communication, define different operations
     */
    public static final String MSG_TYPE_HELLO = "HELLO";
    public static final String MSG_TYPE_KEY_EXCHANGE = "KEY_EXCHANGE";
    public static final String MSG_TYPE_AUTH_REQUEST = "AUTH_REQUEST";
    public static final String MSG_TYPE_AUTH_RESPONSE = "AUTH_RESPONSE";
    public static final String MSG_TYPE_TOTP_CHALLENGE = "TOTP_CHALLENGE";
    public static final String MSG_TOTP_RESPONSE = "TOTP_RESPONSE";
    public static final String MSG_TYPE_FILE_UPLOAD = "FILE_UPLOAD";
    public static final String MSG_TYPE_FILE_DOWNLOAD = "FILE_DOWNLOAD";
    public static final String MSG_TYPE_FILE_LIST = "FILE_LIST";
    public static final String MSG_TYPE_BLOCKCHAIN_QUERY = "BLOCKCHAIN_QUERY";
    public static final String MSG_TYPE_ERROR = "ERROR";
    public static final String MSG_TYPE_GOODBYE = "GOODBYE";

    /**
     * message field identifiers, used for consisten JSON field names in protocol messages
     */
    public static final String FIELD_MESSAGE_TYPE = "type";
    public static final String FIELD_SESSION_ID = "session_id";
    public static final String FIELD_TIMESTAMP = "timestamp";
    public static final String FIELD_NONCE = "nonce";
    public static final String FIELD_PAYLOAD = "payload";
    public static final String FIELD_SIGNATURE = "signature";
    public static final String FIELD_USERNAME = "username";
    public static final String FIELD_PASSWORD = "password";
    public static final String FIELD_TOTP_CODE = "totp_code";
    public static final String FIELD_FILE_NAME = "file_name";
    public static final String FIELD_FILE_SIZE = "file_size";
    public static final String FIELD_FILE_HASH = "file_hash";
    public static final String FIELD_FILE_DATA = "file_data";
    public static final String FIELD_FILE_KEY = "file_key";
    public static final String FIELD_ERROR_CODE = "error_code";
    public static final String FIELD_ERROR_MESSAGE = "error_message";

    /**
     * standardized error codes for protocol error messages between client and server
     */
    public static final int ERROR_AUTHENTICATION_FALED = 1001;
    public static final int ERROR_TOTP_INVALID = 1002;
    public static final int ERROR_SESSION_EXPIRED = 1003;
    public static final int ERROR_FILE_NOT_FOUND = 2001;
    public static final int ERROR_FILE_ACCESS_DENIED = 2002;
    public static final int ERROR_FILE_TOO_LARGE = 2003;
    public static final int ERROR_BLOCKCHAIN_INVALID = 3001;
    public static final int ERROR_SERVER_INTERNAL = 5001;
    public static final int ERROR_PROTOCOL_VERSION = 6001;

    /**
     * cryptographic parameters, key sizes and algorithm choices for the system
     */
    public static final String KYBER_VARIANT = "Kyber1024";
    public static final String DILITHIUM_VARIANT = "Dilithium5";
    public static final String SYMMETRIC_ALGORITHM = "AES/GCM/NoPadding";
    public static final int AES_KEY_SIZE_BITS = 256;
    public static final int GCM_TAG_LENGTH_BITS = 128;
    public static final int GCM_IV_LENGTH_BYTES = 12;
    public static final String HASH_ALGORITHM = "SHA-512";

    /**
     * file operation parameters, controls file transfer and storage behavior
     */
    public static final long MAX_FILE_SIZE_BYTES = 10*1024*1024; // 10 MB
    public static final String DOWNLOAD_DIRECTORY = "./downloads"; 
    public static final String UPLOAD_DIRECTORY = "./uploads";

    /**
     * authentication parameters, controols authentication and session behavior
     */
    public static final int MAX_LOGIN_ATTEMPTS = 3;
    public static final int SESSION_TIMEOUT_SECONDS = 1800; // minutes
    public static final int TOTP_WINDOW_SIZE = 1; // plus or minues 30 seconds
    public static final int TOTP_CODE_DIGITS = 6; 
    public static final int TOTP_TIME_STEP_SECONDS = 30; 
    public static final String TOTP_ALGORITHM = "HmacSHA1";

    /**
     * blockchain parameters, controls blockchain structure and behavior
     */
    public static final int BLOCKCHAIN_MAX_BLOCK_SIZE = 10; // max transactions per block
    public static final String BLOCKCHAIN_FILE = "./stores/blockchain.json"; // storage location
    public static final String GENESIS_BLOCK_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

    /**
     * thread pool parameters for server threading behavior
     */
    public static final int THREAD_POOL_SIZE = 10; 
    public static final int THREAD_POOL_KEEP_ALIVE_SECONDS = 60;

    /**
     * private constructor to prevent instrantiation, we're only using the static constants
     */
    private Constants() {}
}
