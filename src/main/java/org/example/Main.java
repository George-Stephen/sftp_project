package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.example.classes.PGPEncryptionUtil;

import java.io.*;
import java.security.Security;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

public class Main {

    public static void main(String[] args) {

        Security.addProvider(new BouncyCastleProvider());

        try {
            // Encrypt file
            String originalFilePath = "src/main/java/org/example/resources/APP_CPO_20240223_002.tsv";
            String encryptedFilePath = "src/main/java/org/example/resources/encrypted.tsv.zip.pgp";
            String publicKeyFilePath = "src/main/java/org/example/resources/public.asc";
            String zippedFile = zipFile(originalFilePath);
            String outputFile = "src/main/java/org/example/resources/output.tsv";
            encryptFile(zippedFile, encryptedFilePath, publicKeyFilePath);

            // Decrypt file
            String decryptedFilePath = "src/main/java/org/example/resources/decrypted.zip";
            String privateKeyFilePath = "src/main/java/org/example/resources/private.asc";
            String passphrase = "technote";
            decryptFile(encryptedFilePath, decryptedFilePath, privateKeyFilePath, passphrase);
            unzipFile(decryptedFilePath,outputFile);

            // Verify decrypted content
//            BufferedReader reader = new BufferedReader(new FileReader(decryptedFilePath));
//            String line;
//            while ((line = reader.readLine()) != null) {
//                System.out.println(line);
//            }
//            reader.close();

        } catch (IOException | PGPException e) {
            e.printStackTrace();
        }
    }

    public static void encryptFile(String originalFilePath, String encryptedFilePath, String publicKeyFilePath) throws IOException, PGPException {
        FileInputStream fis = new FileInputStream(originalFilePath);
        FileOutputStream fos = new FileOutputStream(encryptedFilePath);
        PGPEncryptionUtil.encryptFile(fis, fos, publicKeyFilePath, true, true);
        fis.close();
        fos.close();
        System.out.println("File encrypted successfully.");
    }

    public static void decryptFile(String encryptedFilePath, String decryptedFilePath, String privateKeyFilePath, String passphrase) throws IOException, PGPException {
        FileInputStream fis = new FileInputStream(encryptedFilePath);
        FileOutputStream fos = new FileOutputStream(decryptedFilePath);
        PGPEncryptionUtil.decryptFile(fis, fos, privateKeyFilePath, passphrase.toCharArray());
        fis.close();
        fos.close();
        System.out.println("File decrypted successfully.");
    }

    public static String zipFile(String inputFile) throws IOException {
        String zippedFileName = inputFile + ".zip";
        try (FileOutputStream fos = new FileOutputStream(zippedFileName);
             BufferedOutputStream bos = new BufferedOutputStream(fos);
             ZipOutputStream zos = new ZipOutputStream(bos)) {
            File file = new File(inputFile);
            try (FileInputStream fis = new FileInputStream(file);
                 BufferedInputStream bis = new BufferedInputStream(fis)) {
                ZipEntry zipEntry = new ZipEntry(file.getName());
                zos.putNextEntry(zipEntry);
                byte[] bytes = new byte[1024];
                int length;
                while ((length = bis.read(bytes)) >= 0) {
                    zos.write(bytes, 0, length);
                }
            }
        }
        return zippedFileName;
    }

    public static void unzipFile(String zippedFile, String outputFile) throws IOException {
        try (FileInputStream fis = new FileInputStream(zippedFile);
             ZipInputStream zis = new ZipInputStream(fis)) {
            ZipEntry zipEntry = zis.getNextEntry();
            try (FileOutputStream fos = new FileOutputStream(outputFile);
                 BufferedOutputStream bos = new BufferedOutputStream(fos)) {
                byte[] buffer = new byte[1024];
                int len;
                while ((len = zis.read(buffer)) > 0) {
                    bos.write(buffer, 0, len);
                }
            }
        }
    }
}
