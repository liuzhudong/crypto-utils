package com.jelly.code.crypto.ecdsa;

import com.jelly.code.crypto.ecdsa.EcdsaCrypto.EcdsaCryptoCurve;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.junit.Before;
import org.junit.Test;

/**
 * TODO
 *
 * @author liuzhudong
 * @version 1.0
 * @date 18/5/30 上午10:36
 */
public class EcdsaCryptoTest {

    private EcdsaCrypto crypto;

    @Before
    public void setUp() throws Exception {
        crypto = EcdsaCrypto.getInstance();
    }

    @Test
    public void keyGen() throws Exception {
        KeyPair keyPair = crypto.keyGen();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        System.out.println(privateKey.getClass().getName());
        System.out.println(privateKey.getAlgorithm());
        System.out.println(privateKey.getFormat());
        System.out.println(crypto.privateKeyToPEM(privateKey));

        System.out.println("==================");

        System.out.println(publicKey.getClass().getName());
        System.out.println(publicKey.getAlgorithm());
        System.out.println(publicKey.getFormat());
        System.out.println(crypto.publicKeyToPEM(publicKey));

    }

    @Test
    public void keyGen1() throws Exception {
        KeyPair keyPair = crypto.keyGen(EcdsaCryptoCurve.PRIME_256_V1);
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        System.out.println(privateKey.getClass().getName());
        System.out.println(publicKey.getClass().getName());
    }

    @Test
    public void publicKeyToPEM() throws Exception {
    }

    @Test
    public void privateKeyToPEM() throws Exception {
    }

    @Test
    public void loadECPrivateKey() throws Exception {
    }

    @Test
    public void loadECPublicKey() throws Exception {
    }

    @Test
    public void getECPublickeyFromPrivateKey() throws Exception {
    }

    @Test
    public void getECPublickeyFromPrivateKey1() throws Exception {
    }

}