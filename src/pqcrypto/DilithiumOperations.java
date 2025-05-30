package pqcrypto;

import org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider; 
import org.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;

import java.security.*;

/**
 * encapsulates dilithium operations needed for creating and verifying digital signatures
 */
public class DilithiumOperations {

    // dilithium5 is the highest security level variant 
    private static final DilithiumParameterSpec DILITHIUM_PARAMS = DilithiumParameterSpec.dilithium5;

    private final SecureRandom secureRandom;

    /**
     * constructor : initializes secrue random parameter
     */
    public DilithiumOperations() {
        
        this.secureRandom = new SecureRandom();
        Security.addProvider(new BouncyCastlePQCProvider());
    }

    /**
     * generates Dilithium key pair, pub and private keys
     * private key : signs messages 
     * public keys : verifies signatures 
     * 
     * @return
     * @throws GeneralSecurityException
     */
    public KeyPair generateKeyPair() throws GeneralSecurityException {

        System.out.println("Generating Key Pair");
        // dilithium key pair generator
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("Dilithium", "BCPQC");

        // initialize with dilithium5 parameters and secure random
        keyGen.initialize(DILITHIUM_PARAMS, secureRandom);

        System.out.println("Key Pair Generated");
        // generate and return keypair
        return keyGen.generateKeyPair();
    }

    /**
     * signs messages using the private key
     * @param privateKey
     * @param message
     * @return
     * @throws GeneralSecurityException
     */
    public byte[] sign(PrivateKey privateKey, byte[] message) throws GeneralSecurityException {

        System.out.println("Signing");

        // signature instance using Dilithium algorithm
        Signature signature = Signature.getInstance("Dilithium", "BCPQC");

        // initialize for signing with the private key
        signature.initSign(privateKey, secureRandom);

        // update with the message to sign
        signature.update(message);
       
        System.out.println("Signed");

        return signature.sign();
        
    }

    public boolean verify(PublicKey publicKey, byte[] message, byte[] signature) throws GeneralSecurityException {

        System.out.println("Verifying");

        // signature instance...
        Signature verifier = Signature.getInstance("Dilithium", "BCPQC");
    
        // initialize for verification with the public key
        verifier.initVerify(publicKey); 

        // update...
        verifier.update(message);

        System.out.println("Verified");

        return verifier.verify(signature);
    }

    /**
     * returns the public key size for Dilithium5
     * @return
     */
    public int getPublicKeySize() {
        System.out.println("(DilithiumOperations.java) pub key size: 2592 bytes");
        return 2592;
    }

    /**
     * returns the private key size for Dilithium5 
     * @return
     */
    public int getPrivateKeySize() {
        System.out.println("(DilithiumOperations.java) priv key size: 4864 bytes");
        return 4864;
    }

    /**
     * returns the size of a signature for Dilithim5
     * @return
     */
    public int getSignatureSize() {

        System.out.println("(DilithiumOperations.java) sig size: 4595 bytes");
        return 4595;
    }
}
