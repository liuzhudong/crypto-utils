/*
 * Copyright & License.
 */

package com.jelly.code.crypto.ecdsa;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

/**
 * EC 椭圆曲线非对称算法工具类
 *
 * @author liuzhudong
 * @version 1.0
 * @date 18/5/29 下午7:23
 */
public class EcdsaCrypto {

    private static final String UTF_8 = "UTF-8";
    private static final String BEGIN_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n";
    private static final String BEGIN_PUBLIC_KEY = "-----BEGIN PUBLIC KEY-----\n";
    private static final String END_PRIVATE_KEY = "\n-----END PRIVATE KEY-----";
    private static final String END_PUBLIC_KEY = "\n-----END PUBLIC KEY-----";
    private static final String LINE_FLAG = "\n";
    private static final String EMPTY_FLAG = "";
    private static final String ALGORITHM = "EC";

    private final Provider provider = new BouncyCastleProvider();

    private EcdsaCrypto() {

    }

    public static EcdsaCrypto getInstance() {
        return EcdsaCryptoHolder.ECKEY_HOLDER;
    }

    public KeyPair keyGen() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        return keyGen(null);
    }

    public KeyPair keyGen(EcdsaCryptoCurve curve) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Security.addProvider(provider);
        curve = curve == null ? EcdsaCryptoCurve.SECP_256_K1 : curve;
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(curve.getCurveName());
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM, provider);
        keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    public String publicKeyToPEM(PublicKey publicKey) throws UnsupportedEncodingException {
        return formatToPem(publicKey.getEncoded(), BEGIN_PUBLIC_KEY, END_PUBLIC_KEY);
    }

    public String privateKeyToPEM(PrivateKey privateKey) throws UnsupportedEncodingException {
        return formatToPem(privateKey.getEncoded(), BEGIN_PRIVATE_KEY, END_PRIVATE_KEY);
    }

    public PrivateKey loadECPrivateKey(String content) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKeyPEM = content.replace(BEGIN_PRIVATE_KEY, EMPTY_FLAG)
            .replace(END_PRIVATE_KEY, EMPTY_FLAG).replace(LINE_FLAG, EMPTY_FLAG);
        byte[] asBytes = Base64.getDecoder().decode(privateKeyPEM);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(asBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePrivate(spec);
    }

    public PublicKey loadECPublicKey(String content) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String strPublicKey = content.replace(BEGIN_PUBLIC_KEY, EMPTY_FLAG)
            .replace(END_PUBLIC_KEY, EMPTY_FLAG).replace(LINE_FLAG, EMPTY_FLAG);
        byte[] asBytes = Base64.getDecoder().decode(strPublicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(asBytes);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM);
        return keyFactory.generatePublic(spec);
    }

    public PublicKey getECPublickeyFromPrivateKey(ECPrivateKey ecPrivateKey)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        return getECPublickeyFromPrivateKey(ecPrivateKey, null);
    }

    public PublicKey getECPublickeyFromPrivateKey(ECPrivateKey ecPrivateKey, EcdsaCryptoCurve curve)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        curve = curve == null ? EcdsaCryptoCurve.SECP_256_K1 : curve;
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM, provider);
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(curve.getCurveName());
        ECPoint Q = ecSpec.getG().multiply(ecPrivateKey.getD());
        ECPublicKeySpec pubSpec = new ECPublicKeySpec(Q, ecSpec);
        return keyFactory.generatePublic(pubSpec);
    }

    private String formatToPem(byte[] encoded, String beginTag, String endTag) throws UnsupportedEncodingException {
        byte[] encodes = Base64.getEncoder().encode(encoded);
        String content = new String(encodes, UTF_8);
        int length = content.length();
        int loops = length / 64;
        int index = 0;
        StringBuilder strb = new StringBuilder(200);
        strb.append(beginTag);
        for (int i = 0; i < loops; i++) {
            strb.append(content.substring(index, index + 64));
            strb.append(LINE_FLAG);
            index += 64;
        }
        strb.append(content.substring(index, length));
        strb.append(endTag);

        return strb.toString();
    }

    public enum EcdsaCryptoCurve {
        PRIME_256_V1("prime256v1"),
        SECP_256_R1("secp256r1"),
        NISTP_256("nistp256"),
        SECP_256_K1("secp256k1"),;

        private String curveName;

        EcdsaCryptoCurve(String curveName) {
            this.curveName = curveName;
        }

        public String getCurveName() {
            return curveName;
        }
    }

    private static class EcdsaCryptoHolder {

        static final EcdsaCrypto ECKEY_HOLDER = new EcdsaCrypto();
    }

}
