import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class ClientCP2 {

	public static void main(String[] args) throws Exception {
		String msg = "Hello SecStore, please prove your identity!";
		Random random = new Random();
		int length;
		length = random.nextInt(10);
		char[] charc = new char[length];
		for (int i =0;i<length;i++){
			charc[i] = msg.charAt(random.nextInt(msg.length()));
		}
		String nonce = new String(charc);

		String msg1 = "Give me your certificate signed by CA";
		InputStream fis = new FileInputStream("cacsertificate.crt");
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);

		System.out.println("Getting file from server...");
		PublicKey CAKey = CAcert.getPublicKey();
    	String serverAddress = "localhost";
    	int port = 4321;
		int numBytes = 0;
		Socket clientSocket = null;
        DataOutputStream toServer = null;
        DataInputStream fromServer = null;
    	FileInputStream fileInputStream = null;
        BufferedInputStream bufferedFileInputStream = null;
		//long timeStarted = System.nanoTime();

		try {
			System.out.println("Establishing connection to server...");
			// Connect to server and get the input and output streams
			clientSocket = new Socket(serverAddress, port);
			toServer = new DataOutputStream(clientSocket.getOutputStream());
			fromServer = new DataInputStream(clientSocket.getInputStream());

			System.out.println("Sending nonce");
			toServer.writeInt(2);
			toServer.writeInt(nonce.getBytes().length);
			toServer.write(nonce.getBytes());

			System.out.println("Receiving signed nonce");
			// reading encrypt msg
			int	encrypt_numBytes = fromServer.readInt();
			// encrypt msg in bytes[]
			byte[] encypt_msg  = new byte[encrypt_numBytes];
			fromServer.readFully(encypt_msg,0,encrypt_numBytes);

			System.out.println("Sending cert req...");
			toServer.writeInt(3);
			toServer.writeInt(msg1.getBytes().length);
			toServer.write(msg1.getBytes());

			System.out.println("Receiving cert..");
			String certString = fromServer.readUTF();
			//
			byte[] cert_byte = Base64.getDecoder().decode(certString);
			//
			InputStream bis = new ByteArrayInputStream(cert_byte);
			X509Certificate CAcert1 =(X509Certificate)cf.generateCertificate(bis);
			PublicKey publicKey = CAcert1.getPublicKey();
			CAcert1.checkValidity();
			CAcert1.verify(CAKey);
			Cipher desCipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			desCipher2.init(Cipher.DECRYPT_MODE, publicKey);
			//decrypt encrypt_msg
			byte[] decypt_msg = desCipher2.doFinal(encypt_msg);
			//
			String decrypt_string = new String(decypt_msg,StandardCharsets.UTF_8);

			if(!decrypt_string.equals(nonce)){
				fromServer.close();
				toServer.close();
				System.out.println("Bye!");
			}

			System.out.println("Handshake for file upload");
			Scanner scanner = new Scanner(System.in);
			String filename;

			while(true) {
				System.out.println("Please enter a file name");
				filename = scanner.next();
					if(filename.equals("exit")){
						break;
					}

				System.out.println("Sending file...");

				Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
				cipher.init(Cipher.ENCRYPT_MODE, publicKey);

				// Generate AES key
				KeyGenerator keyGen = KeyGenerator.getInstance("AES");
				keyGen.init(128);
				SecretKey AESKey = keyGen.generateKey();

				// Encrypt AES key
				byte[] AESKeyBytes = AESKey.getEncoded();
				byte[] encryptedAESKey = cipher.doFinal(AESKeyBytes);

				toServer.writeInt(encryptedAESKey.length);
				toServer.write(encryptedAESKey);
				toServer.flush();

				// Start timer here
				long timeStarted = System.nanoTime();

				// Send the filename
				toServer.writeInt(0);
				toServer.writeInt(filename.getBytes().length);
				toServer.write(filename.getBytes());
				toServer.flush();
				// Open the file
				fileInputStream = new FileInputStream(filename);
				bufferedFileInputStream = new BufferedInputStream(fileInputStream);
//				byte[] fromFileBuffer = new byte[4092];

				// max block length is 117 bytes
				byte[] fromFileBuffer = new byte[117];
				// send the file

				for (boolean fileEnded = false; !fileEnded; ) {
					numBytes = bufferedFileInputStream.read(fromFileBuffer);
//					fileEnded = numBytes < 4092;
					fileEnded = numBytes < 117;
					toServer.writeInt(1);
					toServer.writeInt(numBytes);

					// encrypt file data
					Cipher AESCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
					AESCipher.init(Cipher.ENCRYPT_MODE, AESKey);
					byte[] encryptedFromFileBuffer = AESCipher.doFinal(fromFileBuffer);
					int encryptedNumBytes = encryptedFromFileBuffer.length;

					toServer.writeInt(encryptedNumBytes);
					toServer.write(encryptedFromFileBuffer, 0, encryptedFromFileBuffer.length);
					toServer.flush();
				}
				System.out.println("File sent...");
				bufferedFileInputStream.close();
				fileInputStream.close();

				long timeTaken = System.nanoTime() - timeStarted;
				System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
			}
			System.out.println("Closing connection...");
			toServer.close();
			fromServer.close();
			clientSocket.close();
		} catch (Exception e) {e.printStackTrace();}
//		long timeTaken = System.nanoTime() - timeStarted;
//		System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
	}


}