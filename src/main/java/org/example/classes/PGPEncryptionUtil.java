package org.example.classes;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.*;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;


import java.io.*;
import java.security.SecureRandom;
import java.util.Iterator;

public class PGPEncryptionUtil {

    public static void encryptFile(InputStream inputStream, OutputStream outputStream, String publicKeyFilePath, boolean armor, boolean withIntegrityCheck) throws IOException, PGPException {
        OutputStream encryptedOut = outputStream;

        PGPUtil.setDefaultProvider("BC");

        PGPPublicKey key = readPublicKey(publicKeyFilePath);
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5)
                        .setWithIntegrityPacket(withIntegrityCheck)
                        .setSecureRandom(new SecureRandom())
                        .setProvider("BC"));
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(key)
                .setProvider("BC"));

        OutputStream cOut = encryptedOut;
        if (armor) {
            cOut = new ArmoredOutputStream(cOut);
        }

        OutputStream encryptedData = encGen.open(cOut, new byte[4096]);
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
        OutputStream compressedOut = comData.open(encryptedData);
        PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
        OutputStream literalOut = literalDataGenerator.open(compressedOut,
                PGPLiteralData.BINARY, PGPLiteralData.CONSOLE, inputStream.available(),
                new java.util.Date());
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            literalOut.write(buffer, 0, bytesRead);
        }
        literalOut.close();
        literalDataGenerator.close();
        comData.close();
        encryptedData.close();

        if (armor) {
            cOut.close();
        }
    }

    public static void decryptFile(InputStream inputStream, OutputStream outputStream, String privateKeyFilePath, char[] passphrase) throws IOException, PGPException {
        inputStream = PGPUtil.getDecoderStream(inputStream);
        try {
            PGPObjectFactory pgpF = new PGPObjectFactory(inputStream, new BcKeyFingerprintCalculator());

            PGPEncryptedDataList enc = null;

            Object o = pgpF.nextObject();
            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }

            Iterator<?> it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData) it.next();
                sKey = findSecretKey(privateKeyFilePath, passphrase, pbe.getKeyID());
            }

            if (sKey == null) {
                throw new IllegalArgumentException("Secret key for message not found.");
            }

            InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder()
                    .setProvider("BC").build(sKey));

            PGPObjectFactory plainFact = new PGPObjectFactory(clear, new BcKeyFingerprintCalculator());
            Object message = plainFact.nextObject();

            if (message instanceof PGPCompressedData) {
                PGPCompressedData cData = (PGPCompressedData) message;
                PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream(), new BcKeyFingerprintCalculator());
                message = pgpFact.nextObject();
            }

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData) message;
                InputStream unc = ld.getInputStream();
                int ch;
                while ((ch = unc.read()) >= 0) {
                    outputStream.write(ch);
                }
            } else if (message instanceof PGPOnePassSignatureList) {
                throw new PGPException("Encrypted message contains a signed message - not literal data.");
            } else {
                throw new PGPException("Message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected()) {
                if (!pbe.verify()) {
                    throw new PGPException("Message failed integrity check");
                }
            }
        } catch (PGPException e) {
            throw new PGPException("Error decrypting file", e);
        }
    }

    private static PGPPublicKey readPublicKey(String publicKeyFilePath) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(publicKeyFilePath));
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new BcKeyFingerprintCalculator());
        Iterator<PGPPublicKeyRing> keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = keyRingIter.next();
            Iterator<PGPPublicKey> keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = keyIter.next();
                if (key.isEncryptionKey()) {
                    keyIn.close();
                    return key;
                }
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    private static PGPPrivateKey findSecretKey(String privateKeyFilePath, char[] passphrase, long keyID) throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(privateKeyFilePath));
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn), new BcKeyFingerprintCalculator());
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
        if (pgpSecKey == null) {
            return null;
        }
        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder()
                .setProvider("BC").build(passphrase);
        return pgpSecKey.extractPrivateKey(decryptor);
    }
}


