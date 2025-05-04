package pqcrypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * symmetric encryption operations needed for securing file contents using AES-256 in GCM
 */
public class SymmetricCrypto {
    
    private static final String ALGORITHM = "AES"; 
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE_BITS = 256;
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int GCM_IV_LENGTH_BYTES = 12;

    private final SecureRandom secureRandom;

    /**
     * constructor initializing the secure random generator
     */
    public SymmetricCrypto() {
        this.secureRandom = new SecureRandom();
        System.out.println("(SymmetricCrypto.java) constructor set");
    }

    /**
     * generates a new random AES256 key for symmetric encryption
     * @return
     * @throws NoSuchAlgorithmException
     */
    public SecretKey generateKey() throws NoSuchAlgorithmException {

        System.out.println("(SymmetricCrypto.java) generatung key----------------");

        KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM);
        keyGen.init(KEY_SIZE_BITS, secureRandom);

        System.out.println("(SymmetricCrypto.java) key initialized, generating and returning");
        return keyGen.generateKey();
    }

    public byte[] encrypt(byte[] data, SecretKey key, byte[] associatedData) throws Exception {
        System.out.println("(SymmetricCrypto.java) encrypting---------------");

        // generate random IV 
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);
        System.out.println("(SymmetricCrypto.java) generated IV");

        // gcm parameter specification
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_IV_LENGTH_BYTES, iv);

        // initialize cipher for encryption
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);

        // add associated data if provided
        if (associatedData != null) {
            cipher.updateAAD(associatedData);
            System.out.println("(SymmetricCrypto.java) adde associated data for authentication");
        }

        // encrypt the data
        byte[] ciphertext = cipher.doFinal(data);
        System.out.println("(SymmetricCrypto.java) encryption done");

        // combine IV and ciphertext into one array
        byte[] encryptedData = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encryptedData, 0, iv.length);
        System.arraycopy(ciphertext, 0, encryptedData, iv.length, ciphertext.length);
        System.out.println("(SymmetricCrypto.java) combined IV and ciphertext, returning");
        
        return encryptedData;

    }   

    /**
     * decrypts data (reverses "encrypt" above)
     * @param encryptedData
     * @param key
     * @param associatedData
     * @return
     * @throws Exception
     */
    public byte[] decrypt(byte[] encryptedData, SecretKey key, byte[] associatedData) throws Exception {
        System.out.println("(SymmetricCrypto.java) dycryptin--------------");

        // extract the IV from the encrypted data
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        System.arraycopy(encryptedData, 0, iv, 0, iv.length);
        System.out.println("(SymmetricCrypo.java) IV extracted");

        // create GCM parameter specification
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);

        // inittialize cipher for decryption
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);

        // add associated data if provided
        if (associatedData != null) {
            cipher.updateAAD(associatedData);
            System.out.println("(SymmetricCrypo.java) added associated data for authentication");
        }

        // decrypt data excluding the IV
        byte[] ciphertext = new byte[encryptedData.length - iv.length];
        System.arraycopy(encryptedData, iv.length, ciphertext, 0, ciphertext.length);

        System.out.println("(SymmetricCrypo.java) decrypting ciphertext");

        byte[] plaintext = cipher.doFinal(ciphertext);
    
        System.out.println("(SymmetricCrypo.java) decryption and authentication successful");
        return plaintext;
    }

    /**
     * converts raw byte array into a SecretKey object
     * @param keyBytes
     * @return
     */
    public SecretKey convertBytesToKey(byte[] keyBytes) {
        System.out.println("(SymmetricCrypto.java) converting byte array to SecretKey");
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    /**
     * get key size in bytes
     * @return
     */
    public int getKeySize() {
        System.out.println("(symmetricCrypto.java) key size: " + (KEY_SIZE_BITS/8) + " bytes");
        return KEY_SIZE_BITS/8; 
    }

    /**
     * get iv size in bytes
     * @return
     */
    public int getIVSize() {
        System.out.println("(SymmetricCrypto.java) iv size: " + GCM_IV_LENGTH_BYTES + " bytes");
        return GCM_IV_LENGTH_BYTES;
    }

    /**
     * get the auth tag size in bytes
     * @return
     */
    public int getTagSize() {
        System.out.println("(SymmetricCrypto.java) tag size: " + (GCM_TAG_LENGTH_BITS/8) + " bytes");
        return GCM_TAG_LENGTH_BITS/8; 
    }
}
