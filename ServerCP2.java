import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ServerCP2 {

	public static void main(String[] args) throws Exception {
		String reply = "Hello, this is Secstore!";
    	int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);
		ServerSocket serverSocket = new ServerSocket(6666);
		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;
		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;
		PrivateKey privateKey;
		SecretKey sessionKey = null;
		final int FILE_SIZE = Integer.MAX_VALUE;
		privateKey = PrivateKeyReader.get("private_key.der");
		InputStream fis = new FileInputStream("certificate_1003625.crt");
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			while (!connectionSocket.isClosed()) {
				int packetType = fromClient.readInt();

				// If the packet is for transferring the filename
				if (packetType == 0) {
					int numBytes = fromClient.readInt();
					byte[] filename = new byte[numBytes];

					System.out.println("Receiving file...");
					fromClient.readFully(filename, 0, numBytes);
					fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				} else if (packetType==4) {
					int AESNumBytes = fromClient.readInt();
					byte[] AESSessionKey = new byte[AESNumBytes];
					fromClient.readFully(AESSessionKey, 0, AESNumBytes);
					Cipher decryptCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
					byte[] decAESSessionKey = decryptCipher.doFinal(AESSessionKey);
					sessionKey = new SecretKeySpec(decAESSessionKey, 0, decAESSessionKey.length, "AES");

				} else if (packetType == 1) {
					int numBytes = fromClient.readInt();

					int encryptedNumBytes = fromClient.readInt();

//					byte[] block = new byte[numBytes];
					byte[] block = new byte[encryptedNumBytes];
//					fromClient.readFully(block, 0, numBytes);
					fromClient.readFully(block, 0, encryptedNumBytes);

					Cipher decryptCipher2 = Cipher.getInstance("AES/ECB/PKCS5Padding");
					decryptCipher2.init(Cipher.DECRYPT_MODE, sessionKey);
					byte[] decryptedBlock = decryptCipher2.doFinal(block);

					if (numBytes > 0) {
//						bufferedFileOutputStream.write(block, 0, numBytes);
						bufferedFileOutputStream.write(decryptedBlock, 0, numBytes);
					}
//					if (numBytes < 4092) {
					if (numBytes < 117) {
						System.out.println("File is received");
						if (bufferedFileOutputStream != null) {
							bufferedFileOutputStream.close();
							fileOutputStream.close();
						}

					}

				}	else if (packetType==2){
					System.out.println(("Receiving nonce"));
					// reading the msg
					int numBytes = fromClient.readInt();
					// msg in bytes[]
					byte[] msg = new byte[numBytes];
					fromClient.readFully(msg,0,numBytes);
					Cipher desCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					desCipher.init(Cipher.ENCRYPT_MODE,privateKey);
					//convert string to byte
					String nonce = new String(msg,0,numBytes);
					byte[] encrypt = desCipher.doFinal(nonce.getBytes());

					System.out.println(("Sending signed nonce"));
					toClient.writeInt(encrypt.length);
					toClient.write(encrypt);

				}	else if (packetType==3){
					System.out.println(("Receiving cert req..."));
					// reading the msg1
					int numBytes1 = fromClient.readInt();
					// msg1 in bytes[]
					byte[] msg1 = new byte[numBytes1];
					fromClient.readFully(msg1,0,numBytes1);
					System.out.println(new String(msg1,0,numBytes1));

					System.out.println(("Sending cert..."));
                    toClient.writeUTF(Base64.getEncoder().encodeToString(CAcert.getEncoded()));
                    //toClient.writeInt(stringCert.getBytes().length);
					//toClient.write(stringCert.getBytes());
				}

			}
		} catch (Exception e) {e.printStackTrace();}

	}

}

