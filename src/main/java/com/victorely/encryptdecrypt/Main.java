package com.victorely.encryptdecrypt;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Objects;

public class Main {

    private static final Logger LOGGER = LogManager.getLogger(Main.class.getName());

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory certFactory = null;
        try {
            certFactory = CertificateFactory
                    .getInstance("X.509", "BC");
        } catch (CertificateException | NoSuchProviderException e) {
            LOGGER.error(e.getMessage(), e);
        }

        X509Certificate certificate = null;
        try {
            certificate = (X509Certificate) Objects.requireNonNull(certFactory)
                    .generateCertificate(new FileInputStream("VictorELY.cer"));
        } catch (CertificateException | FileNotFoundException e) {
            LOGGER.error(e.getMessage(), e);
        }

        char[] keystorePassword = "password".toCharArray();
        char[] keyPassword = "password".toCharArray();

        KeyStore keystore = null;
        try {
            keystore = KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            LOGGER.error(e.getMessage(), e);
        }
        try {
            Objects.requireNonNull(keystore).load(new FileInputStream("VictorELY.p12"), keystorePassword);
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            LOGGER.error(e.getMessage(), e);
        }
        PrivateKey privateKey = null;
        try {
            privateKey = (PrivateKey) Objects.requireNonNull(keystore).getKey("baeldung", keyPassword);
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
            LOGGER.error(e.getMessage(), e);
        }

        String secretMessage = "My password is 123456Seven";
        System.out.println("Original Message : " + secretMessage);
        byte[] stringToEncrypt = secretMessage.getBytes();
        byte[] encryptedData = new byte[0];
        try {
            encryptedData = BouncyCastleCrypto.encryptData(stringToEncrypt, certificate);
        } catch (CertificateEncodingException | CMSException | IOException e) {
            LOGGER.error(e.getMessage(), e);
        }
        System.out.println("Encrypted Message : " + new String(encryptedData));
        byte[] rawData = new byte[0];
        try {
            rawData = BouncyCastleCrypto.decryptData(encryptedData, privateKey);
        } catch (CMSException e) {
            LOGGER.error(e.getMessage(), e);
        }
        String decryptedMessage = new String(rawData);
        System.out.println("Decrypted Message : " + decryptedMessage);

        byte[] signedData = new byte[0];
        try {
            signedData = BouncyCastleCrypto.signData(rawData, certificate, privateKey);
        } catch (CertificateEncodingException | OperatorCreationException | CMSException | IOException e) {
            LOGGER.error(e.getMessage(), e);
        }
        Boolean check = null;
        try {
            check = BouncyCastleCrypto.verifSignData(signedData);
        } catch (CMSException | IOException | OperatorCreationException | CertificateException e) {
            LOGGER.error(e.getMessage(), e);
        }
        System.out.println(check);

    }

}
