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
    
        System.out.println("(KyberOperations.java) generating key pair--------------");
    
        // get kyber key pair generator 
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Kyber", "BCPQC");
        System.out.println("(KyberOperations.java) set instance");
        // initialize with Kyber 1024 parameters and secure random
        keyGen.initialize(KYBER_PARAMS, secureRandom);
        System.out.println("(KyberOperations.java) initialized for generation, generating and returnign");
        return keyGen.generateKeyPair();
    }

    public SecretKeyWithEncapsulation encapsulateWithSecret(PublicKey publicKey) throws GeneralSecurityException {
        System.out.println("(KyberOperations) encapsulating with secret---------------");

        KeyGenerator keyGen = KeyGenerator.getInstance("Kyber", "BCPQC");
        System.out.println("KyberOps: instance set");
        
        keyGen.init(new KEMGenerateSpec(publicKey, "AES"), secureRandom);
        System.out.println("KyberOps: initialized");

        // cast directly to SecretKeyWithEncaps... to get both key and encapsulation 
        SecretKeyWithEncapsulation result = (SecretKeyWithEncapsulation) keyGen.generateKey();
        System.out.println("KyberOps: generated key and encapsulation");

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

        System.out.println("(KyberOperations.java) encapsulating-----------------");
        
        KeyGenerator keyGen = KeyGenerator.getInstance("Kyber", "BCPQC"); // KEM generator for encapsulation
        System.out.println("(KyberOperations.java) instance set");
        keyGen.init(new KEMGenerateSpec(publicKey, "AES"), secureRandom); // inititialize with public key
        System.out.println("(KyberOperations.java) initialized");
        SecretKeyWithEncapsulation secKey = (SecretKeyWithEncapsulation) keyGen.generateKey(); // generate
        System.out.println("(KyberOperations.java) generated, getting and returning encapsulated key");

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

        System.out.println("(KyberOperations.java) decapsulating---------------");

        KeyGenerator keyGen = KeyGenerator.getInstance("Kyber", "BCPQC"); // extractor 
        System.out.println("(KyberOperations.java) instance set");
        keyGen.init(new KEMExtractSpec(privateKey, ciphertext, "AES")); // initialize with private key and ciphertext (encapsulated public key)
        System.out.println("(KyberOperations.java) initialized");
        SecretKey secretKey = keyGen.generateKey(); // extract
        System.out.println("(KyberOperations.java) generated, getting and returning decapsulated key");

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
