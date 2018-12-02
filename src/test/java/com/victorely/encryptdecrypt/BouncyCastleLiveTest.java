package com.victorely.encryptdecrypt;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BouncyCastleLiveTest {

    private char[] p12Password = "password".toCharArray();
    private char[] keyPassword = "password".toCharArray();

    @Test
    void givenCryptographicResource_whenOperationSuccess_returnTrue() throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, IOException, KeyStoreException, UnrecoverableKeyException, CMSException, OperatorCreationException {
        Security.addProvider(new BouncyCastleProvider());

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
        String certificatePath = "VictorELY.cer";
        X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new FileInputStream(certificatePath));
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        String privateKeyPath = "VictorELY.p12";
        keystore.load(new FileInputStream(privateKeyPath), p12Password);
        PrivateKey privateKey = (PrivateKey) keystore.getKey("baeldung", keyPassword);
        String secretMessage = "My password is 123456Seven";
        System.out.println("Original Message : " + secretMessage);
        byte[] stringToEncrypt = secretMessage.getBytes();
        byte[] encryptedData = BouncyCastleCrypto.encryptData(stringToEncrypt, certificate);
        byte[] rawData = BouncyCastleCrypto.decryptData(encryptedData, privateKey);
        String decryptedMessage = new String(rawData);
        assertEquals(decryptedMessage, secretMessage);
        byte[] signedData = BouncyCastleCrypto.signData(rawData, certificate, privateKey);
        boolean check = BouncyCastleCrypto.verifSignData(signedData);
        assertTrue(check);
    }
}