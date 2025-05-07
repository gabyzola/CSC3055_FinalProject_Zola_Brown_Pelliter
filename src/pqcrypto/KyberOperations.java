package pqcrypto;

import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.KEMExtractSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec; 

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*; 

/**
 * class contains all kyber operations needed for secure key exchange 
 */
public class KyberOperations {

    //u sing kyber 1024
    private static final KyberParameterSpec KYBER_PARAMS = KyberParameterSpec.kyber1024; 

    private final SecureRandom secureRandom;

    public KyberOperations() {
        
        this.secureRandom = new SecureRandom();
        // register bc pqc provider for kyber support
        Security.addProvider(new BouncyCastlePQCProvider());
        System.out.println("(KyberOperations.java) constructor set");

    }

    /**
     * generates a new kyber key pair, public and private 
     * @return 
     * @throws GeneralSecurityException 
     */
    public KeyPair generateKeyPair() throws GeneralSecurityException {
    
        System.out.println("Generating Key Pair");
        // get kyber key pair generator 
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        // initialize with Kyber 1024 parameters and secure random
        keyGen.initialize(KYBER_PARAMS, secureRandom);
        return keyGen.generateKeyPair();
    }

    public SecretKeyWithEncapsulation encapsulateWithSecret(PublicKey publicKey) throws GeneralSecurityException {

        KeyGenerator keyGen = KeyGenerator.getInstance("Kyber", "BCPQC");
        
        keyGen.init(new KEMGenerateSpec(publicKey, "AES"), secureRandom);

        // cast directly to SecretKeyWithEncaps... to get both key and encapsulation 
        SecretKeyWithEncapsulation result = (SecretKeyWithEncapsulation) keyGen.generateKey();

        System.out.println("Key Pai Generated...Returning");

        return result; 
    }

    /**
     * encapsulates a shared secret using the receiver's public key
     * 
     * @param publicKey
     * @return
     * @throws GeneralSecurityException
     */
    public byte[] encapsulate(PublicKey publicKey) throws GeneralSecurityException {

        System.out.println("Encapsulating Key");

        KeyGenerator keyGen = KeyGenerator.getInstance("Kyber", "BCPQC"); // KEM generator for encapsulation
        keyGen.init(new KEMGenerateSpec(publicKey, "AES"), secureRandom); // inititialize with public key
        SecretKeyWithEncapsulation secKey = (SecretKeyWithEncapsulation) keyGen.generateKey(); // generate

        System.out.println("Key Encapsulated");

        return secKey.getEncapsulation();
    }

    /**
     * decapsulates shared key using the private key
     * 
     * @param privateKey
     * @param ciphertext
     * @return
     * @throws GeneralSecurityException
     */
    public byte[] decapsulate(PrivateKey privateKey, byte[] ciphertext) throws GeneralSecurityException {

        System.out.println("De-capsulating Key");

        KeyGenerator keyGen = KeyGenerator.getInstance("Kyber", "BCPQC"); // extractor 
        keyGen.init(new KEMExtractSpec(privateKey, ciphertext, "AES")); // initialize with private key and ciphertext (encapsulated public key)
        SecretKey secretKey = keyGen.generateKey(); // extract

        System.out.println("Key De-capsulated");

        return secretKey.getEncoded(); 
    }

    /**
     * utility method : returns public key size in bytes
     * @return
     */
    public int getPublicKeySize() {
        System.out.println("(KyberOperations.java) pub key size: 1568 bytes");
        return 1568;
    }

    /**
     * utility method : returns ciphertext size in bytes
     * @return
     */
    public int getCiphertextSie() {
        System.out.println("(KyberOperations.java) cipher text (encapsulated key) size: 1568 bytes");
        return 1568;
    }

    /**
     * utility method : get shared secret size in bytes
     * @return
     */
    public int getSharedSecretSize() {
        System.out.println("(KyberOperations.java) shared secret size: 32 bytes");
        return 32; 
    }
    
}