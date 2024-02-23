package org.example.classes;


import com.jcraft.jsch.*;
import org.bouncycastle.openpgp.PGPException;

import java.io.*;

public class SFTPWithPGP {

    public static void uploadFileWithPGPEncryption(String localFilePath, String remoteFilePath, String publicKeyFilePath, String sftpHost, int sftpPort, String sftpUsername, String sftpPassword) throws JSchException, IOException, PGPException, SftpException {
        JSch jsch = new JSch();
        Session session = jsch.getSession(sftpUsername, sftpHost, sftpPort);
        session.setPassword(sftpPassword);
        session.setConfig("StrictHostKeyChecking", "no");
        session.connect();

        ChannelSftp channelSftp = (ChannelSftp) session.openChannel("sftp");
        channelSftp.connect();

        FileInputStream fis = new FileInputStream(localFilePath);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PGPEncryptionUtil.encryptFile(fis, baos, publicKeyFilePath, true, true);

        InputStream inputStream = new ByteArrayInputStream(baos.toByteArray());
        channelSftp.put(inputStream, remoteFilePath);

        inputStream.close();
        fis.close();
        channelSftp.disconnect();
        session.disconnect();
    }

    public static void downloadFileWithPGPDecryption(String remoteFilePath, String localFilePath, String privateKeyFilePath, String passphrase, String sftpHost, int sftpPort, String sftpUsername, String sftpPassword) throws JSchException, IOException, PGPException, SftpException {
        JSch jsch = new JSch();
        Session session = jsch.getSession(sftpUsername, sftpHost, sftpPort);
        session.setPassword(sftpPassword);
        session.setConfig("StrictHostKeyChecking", "no");
        session.connect();

        ChannelSftp channelSftp = (ChannelSftp) session.openChannel("sftp");
        channelSftp.connect();

        InputStream inputStream = channelSftp.get(remoteFilePath);
        FileOutputStream fos = new FileOutputStream(localFilePath);

        PGPEncryptionUtil.decryptFile(inputStream, fos, privateKeyFilePath, passphrase.toCharArray());

        fos.close();
        channelSftp.disconnect();
        session.disconnect();
    }
}
