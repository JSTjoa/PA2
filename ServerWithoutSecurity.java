import java.awt.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import javax.crypto.Cipher;
import java.security.*;

public class ServerWithoutSecurity {

	public static void main(String[] args) throws Exception {
		String reply = "Hello, this is Secstore!";
    	int port = 4321;
    	if (args.length > 0) port = Integer.parseInt(args[0]);

		ServerSocket welcomeSocket = null;
		Socket connectionSocket = null;
		DataOutputStream toClient = null;
		DataInputStream fromClient = null;

		FileOutputStream fileOutputStream = null;
		BufferedOutputStream bufferedFileOutputStream = null;
		PrivateKey privateKey;

		privateKey = PrivateKeyReader.get("/Users/kaikang/Desktop/PA2/private_key.der");
		InputStream fis = new FileInputStream("/Users/kaikang/Desktop/PA2/certificate_1003625.crt");
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
		String stringCert = CAcert.toString();

		try {
			welcomeSocket = new ServerSocket(port);
			connectionSocket = welcomeSocket.accept();
			fromClient = new DataInputStream(connectionSocket.getInputStream());
			toClient = new DataOutputStream(connectionSocket.getOutputStream());

			while (!connectionSocket.isClosed()) {


				int packetType = fromClient.readInt();

				// If the packet is for transferring the filename
				if (packetType == 0) {

					System.out.println("Receiving file...");

					int numBytes = fromClient.readInt();
					byte [] filename = new byte[numBytes];
					// Must use read fully!
					// See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
					fromClient.readFully(filename, 0, numBytes);

					fileOutputStream = new FileOutputStream("recv_"+new String(filename, 0, numBytes));
					bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

				// If the packet is for transferring a chunk of the file
				} else if (packetType == 1) {

					int numBytes = fromClient.readInt();
					byte [] block = new byte[numBytes];
					fromClient.readFully(block, 0, numBytes);

					if (numBytes > 0)
						bufferedFileOutputStream.write(block, 0, numBytes);

					if (numBytes < 117) {
						System.out.println("Closing connection...");

						if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
						if (bufferedFileOutputStream != null) fileOutputStream.close();
						fromClient.close();
						toClient.close();
						connectionSocket.close();
					}
				}	else if (packetType==2){
					System.out.println(("Receiving msg..."));
					// reading the msg
					int numBytes = fromClient.readInt();
					// msg in bytes[]
					byte[] msg = new byte[numBytes];
					fromClient.readFully(msg,0,numBytes);
					System.out.println(new String(msg,0,numBytes));

					MessageDigest md = MessageDigest.getInstance("MD5");
					// msg hashed
					md.update(reply.getBytes());
					// hashed msg to byte[]
					byte[] byt = md.digest();
					Cipher desCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
					desCipher.init(Cipher.ENCRYPT_MODE,privateKey);
					// encrypt hashed msg
					byte[] encrypt = desCipher.doFinal(byt);

					System.out.println(("Sending signed msg..."));
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
