package pqcrypto;

import javax.crypto.SecretKey;

/*
 * helper class to hold the result of file encryption in CryptoManager.encryptFile
 */
public class FileEncryptionResult {
    private final byte[] encryptedData;
    private final SecretKey fileKey;

    public FileEncryptionResult(byte[] encryptedData, SecretKey fileKey) {
        this.encryptedData = encryptedData;
        this.fileKey = fileKey;
    }

    /**
     * gets the encrypted file data
     * @return
     */
    public byte[] getEncryptedData() {
        return this.encryptedData;
    }

    /**
     * gets the file encryption key
     * @return
     */
    public SecretKey getFileKey() {
        return this.fileKey; 
    }
}
