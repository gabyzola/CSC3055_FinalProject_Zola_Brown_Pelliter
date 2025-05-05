package pqcrypto;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import common.Constants;
import merrimackutil.codec.Base32;


/**
 * handles time based one time password ops for multi factor authentication
 * follows RFC 6238 for TOTP and RFC 4226 for HOTP and is compatible with the authenticator app thingy
 */
public class TOTPManager {
    
    private final int timeStep; 
    private final int codeDigits; 
    private final int windowSize;
    private final SecureRandom secureRandom;

    /**
     * creates a new TOTPManager with custom parameters
     * @param timeStep
     * @param codeDigits
     * @param windowSize
     */
    public TOTPManager(int timeStep, int codeDigits, int windowSize) {
        this.timeStep = timeStep;
        this.codeDigits = codeDigits;
        this.windowSize = windowSize;
        this.secureRandom = new SecureRandom();
    }
    
    /**
     * creates a new TOTPManager with default parameters
     */
    public TOTPManager() {
        this(Constants.TOTP_TIME_STEP_SECONDS, Constants.TOTP_CODE_DIGITS, Constants.TOTP_WINDOW_SIZE);
    }

    /**
     * generates a nw random TOTP secret
     * @return
     */
    public String generateSecret() {
        byte[] secret = new byte[20];
        secureRandom.nextBytes(secret);
        return Base32.encodeToString(secret, false);
    }

    /**
     * gets the curretn TOTP code for a given secret 
     * @param secret
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public String getCurrentCode(String secret) throws NoSuchAlgorithmException, InvalidKeyException {
        long currentTime = Instant.now().getEpochSecond();
        return generateCode(secret, currentTime);
    }

    /**
     * generates a TOTP code for a specific window
     * @param secret
     * @param time
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public String generateCode(String secret, long time) throws NoSuchAlgorithmException, InvalidKeyException {
        
        long counter = time/timeStep; // calculate the time counter 
        byte[] counterBytes = ByteBuffer.allocate(8).putLong(counter).array(); // convert counter to byte array
        byte[] secretBytes = Base32.decode(secret); // decode the base 32 secret -> raw secret bytes

        // calculate HMAC-SHA1 hash
        Mac mac = Mac.getInstance(Constants.TOTP_ALGORITHM);
        SecretKeySpec keySpec = new SecretKeySpec(secretBytes, Constants.TOTP_ALGORITHM);
        mac.init(keySpec);
        byte[] hash = mac.doFinal(counterBytes);

        // exrtrac the TOTPcode from the hash using dynamic truncation
        return truncateHash(hash);
    }

    /**
     * extracts a TOTP code from a hash using dynamic truncation
     * @param hash
     * @return
     */
    private String truncateHash(byte[] hash) {
        int offset = hash[hash.length - 1] & 0xF;

        int binary = ((hash[offset] & 0x7F) << 24) | ((hash[offset + 1] & 0xFF) << 16) | ((hash[offset + 2] & 0xFF) << 8) | ((hash[offset + 3] & 0xFF));

        int modulo = (int) Math.pow(10, codeDigits);
        int code = binary % modulo;

        return String.format("%0" + codeDigits + "d", code);
    }

    public boolean verifyCode(String secret, String code) {

        System.out.println("TOTPManager: verifying totp code");

        // check length and character types
        if (code == null || code.length() != codeDigits || !code.matches("\\d+")) {
            System.out.println("TOTPManager: ERROR: failed initial if case");
            return false; 
        }

        try {
            long currentTime = Instant.now().getEpochSecond();

            // check codes within the time window
            for (int i = -windowSize; i <= windowSize; i++) {
                long timeToCheck = currentTime + (i * timeStep);
                String expectedCode = generateCode(secret, timeToCheck);

                if (expectedCode.equals(code)) {
                    System.out.println("TOTPManager: totp code valid");
                    return true;
                }
            }
        } catch (Exception e) {
            System.out.println("TOTPManager: ERROR: error verifying code");
            return false; 
        }

        System.out.println("TOTPManager: invalid totp code");
        return false;

    }

    /**
     * generates a URI for TOTP setup that can be converted into a QR code for easy scanning
     * @param issuer
     * @param account
     * @param secret
     * @return
     */
    public String generateTotpUri(String issuer, String account, String secret) {

        StringBuilder uri = new StringBuilder("otpauth://totp/");

        // add issuer and account
        if (issuer != null && !issuer.isEmpty()) {
            uri.append(issuer).append(":");
        }

        uri.append(account);

        uri.append("?secret=").append(secret);

        if (issuer != null && !issuer.isEmpty()) {
            uri.append("&issuer=").append(issuer);
        }

        uri.append("&algorithm=SHA1");
        uri.append("&digits=").append(codeDigits);
        uri.append("&period=").append(timeStep);

        return uri.toString();

    }

}
