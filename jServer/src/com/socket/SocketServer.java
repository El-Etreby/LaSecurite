package com.socket;

import java.io.*;

import java.net.*;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

//import com.sun.org.apache.xml.internal.security.algorithms.SignatureAlgorithm;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

class ServerThread extends Thread {

	public SocketServer server = null;
	public Socket socket = null;
	public int ID = -1;
	public String username = "";
	public ObjectInputStream streamIn = null;
	public ObjectOutputStream streamOut = null;
	public ServerFrame ui;

	public ServerThread(SocketServer _server, Socket _socket) {
		super();
		server = _server;
		socket = _socket;
		ID = socket.getPort();
		ui = _server.ui;
	}

	public void send(Message msg) {
		try {
			streamOut.writeObject(msg);
			streamOut.flush();
		} catch (IOException ex) {
			System.out.println("Exception [SocketClient : send(...)]");
		}
	}

	public int getID() {
		return ID;
	}

	@SuppressWarnings("deprecation")
	public void run() {
		ui.jTextArea1.append("\nServer Thread " + ID + " running.");
		while (true) {
			try {
				Message msg = (Message) streamIn.readObject();
				server.handle(ID, msg);
			} catch (Exception ioe) {
				System.out.println(ID + " ERROR reading: " + ioe.getMessage());
				server.remove(ID);
				stop();
			}
		}
	}

	public void open() throws IOException {
		streamOut = new ObjectOutputStream(socket.getOutputStream());
		streamOut.flush();
		streamIn = new ObjectInputStream(socket.getInputStream());
	}

	public void close() throws IOException {
		if (socket != null)
			socket.close();
		if (streamIn != null)
			streamIn.close();
		if (streamOut != null)
			streamOut.close();
	}
}

public class SocketServer implements Runnable {

	public ServerThread clients[];
	public ServerSocket server = null;
	public Thread thread = null;
	public int clientCount = 0, port = 13000;
	public ServerFrame ui;
	public Database db;

////////////////////////////////////DH attributes/////////////////////////////////////
//----> to be returned to default after the Hmac and AES used //////////////////////

	PrivateKey privateKey;
	public PublicKey publicKey;
	public PublicKey receivedPublicKey;
	byte[] secretKey;
	static String IV = "RandomInitVector";
////////////////////////////////////end of DH attributes/////////////////////////////////////

	public SocketServer(ServerFrame frame) {

		clients = new ServerThread[50];
		ui = frame;
		db = new Database(ui.filePath);

		try {
			server = new ServerSocket(port);
			port = server.getLocalPort();
			ui.jTextArea1
					.append("Server startet. IP : " + InetAddress.getLocalHost() + ", Port : " + server.getLocalPort());
			start();
		} catch (IOException ioe) {
			ui.jTextArea1.append("Can not bind to port : " + port + "\nRetrying");
			ui.RetryStart(0);
		}
	}

	public SocketServer(ServerFrame frame, int Port) {

		clients = new ServerThread[50];
		ui = frame;
		port = Port;
		db = new Database(ui.filePath);

		try {
			server = new ServerSocket(port);
			port = server.getLocalPort();
			ui.jTextArea1
					.append("Server startet. IP : " + InetAddress.getLocalHost() + ", Port : " + server.getLocalPort());
			start();
		} catch (IOException ioe) {
			ui.jTextArea1.append("\nCan not bind to port " + port + ": " + ioe.getMessage());
		}
	}

	public void run() {
		while (thread != null) {
			try {
				ui.jTextArea1.append("\nWaiting for a client ...");
				addThread(server.accept());
			} catch (Exception ioe) {
				ui.jTextArea1.append("\nServer accept error: \n");
				ui.RetryStart(0);
			}
		}
	}

	public void start() {
		if (thread == null) {
			thread = new Thread(this);
			thread.start();
		}
	}

	@SuppressWarnings("deprecation")
	public void stop() {
		if (thread != null) {
			thread.stop();
			thread = null;
		}
	}

	private int findClient(int ID) {
		for (int i = 0; i < clientCount; i++) {
			if (clients[i].getID() == ID) {
				return i;
			}
		}
		return -1;
	}

	public synchronized void handle(int ID, Message msg) throws UnsupportedEncodingException {
		if (msg.content.equals(".bye")) {
			Announce("signout", "SERVER", msg.sender);
			remove(ID);
		} else {
			if (msg.type.equals("login")) {
				if (findUserThread(msg.sender) == null && !msg.content.equals("serverDh")) {
					// decrypt password before login
					String base64key = new String(Base64.encodeBase64(secretKey));
					System.out.println("encrypted passord on login server side----->" + msg.content);
					Encryptor e = new Encryptor("de", base64key, IV, msg.content);
					String DePassword = e.getText();
					System.out.println("dycrypted passord on login server side----->" + DePassword);
					if (db.checkLogin(msg.sender, DePassword)) {
						String jwt = createJWT(msg.sender, "secret");
						clients[findClient(ID)].username = msg.sender;
						clients[findClient(ID)]
								.send(new Message("login", "SERVER", "TRUE", jwt, "false", null, msg.HMAC));
						Announce("newuser", "SERVER", msg.sender);
						SendUserList(msg.sender);
					} else {
						clients[findClient(ID)]
								.send(new Message("login", "SERVER", "FALSE", msg.sender, "false", null, msg.HMAC));
					}
				} else if (msg.content.equals("serverDh")) {
					receivedPublicKey = msg.pmKey;
					generateKeys();
					generateCommonSecretKey();
					System.out.println("server side secret key------>" + new String(secretKey));
					clients[findClient(ID)].send(new Message("encryptpasswordlogin", "SERVER", "serverDhReply",
							msg.sender, "true", publicKey, "not HMAC"));
				} else {
					clients[findClient(ID)]
							.send(new Message("login", "SERVER", "FALSE", msg.sender, "false", null, msg.HMAC));
				}
			} else if (msg.type.equals("message")) {
				if (msg.recipient.equals("All")) {
					Announce("message", msg.sender, msg.content);
				} else {

					findUserThread(msg.recipient).send(
							new Message(msg.type, msg.sender, msg.content, msg.recipient, msg.dh, msg.pmKey, msg.HMAC));
					clients[findClient(ID)].send(
							new Message(msg.type, msg.sender, msg.content, msg.recipient, msg.dh, msg.pmKey, msg.HMAC));

				}
			} else if (msg.type.equals("test")) {
				clients[findClient(ID)].send(new Message("test", "SERVER", "OK", msg.sender, "false", null, msg.HMAC));
			} else if (msg.type.equals("signup")) {
				if (findUserThread(msg.sender) == null && !msg.content.equals("serverDh")) {
					if (!db.userExists(msg.sender)) {
						// decrypt password before working
						System.out.println("encrypted passord on login server side----->" + msg.content);
						String base64key = new String(Base64.encodeBase64(secretKey));
						Encryptor e = new Encryptor("de", base64key, IV, msg.content);
						String DePassword = e.getText();
						System.out.println("decrypted passord on login server side----->" + DePassword);
						db.addUser(msg.sender, DePassword);
						String jwt = createJWT(msg.sender, "secret");
						clients[findClient(ID)].username = msg.sender;
						clients[findClient(ID)]
								.send(new Message("signup", "SERVER", "TRUE", msg.sender, "false", null, msg.HMAC));
						clients[findClient(ID)]
								.send(new Message("login", "SERVER", "TRUE", jwt, "false", null, msg.HMAC));
						Announce("newuser", "SERVER", msg.sender);
						SendUserList(msg.sender);
					} else {
						clients[findClient(ID)]
								.send(new Message("signup", "SERVER", "FALSE", msg.sender, "false", null, msg.HMAC));
					}
				} else if (msg.content.equals("serverDh")) {
					receivedPublicKey = msg.pmKey;
					generateKeys();
					generateCommonSecretKey();
					System.out.println("server side secret key------>" + new String(secretKey));
					clients[findClient(ID)].send(new Message("encryptpassword", "SERVER", "serverDhReply", msg.sender,
							"true", publicKey, "not HMAC"));
				} else {
					clients[findClient(ID)]
							.send(new Message("signup", "SERVER", "FALSE", msg.sender, "false", null, msg.HMAC));
				}
			} else if (msg.type.equals("upload_req")) {
				if (msg.recipient.equals("All")) {
					clients[findClient(ID)].send(new Message("message", "SERVER", "Uploading to 'All' forbidden",
							msg.sender, "false", null, msg.HMAC));
				} else {
					findUserThread(msg.recipient).send(
							new Message("upload_req", msg.sender, msg.content, msg.recipient, "false", null, msg.HMAC));
				}
			} else if (msg.type.equals("upload_res")) {
				if (!msg.content.equals("NO")) {
					String IP = findUserThread(msg.sender).socket.getInetAddress().getHostAddress();
					findUserThread(msg.recipient)
							.send(new Message("upload_res", IP, msg.content, msg.recipient, "false", null, msg.HMAC));
				} else {
					findUserThread(msg.recipient).send(
							new Message("upload_res", msg.sender, msg.content, msg.recipient, "false", null, msg.HMAC));
				}
			}
		}
	}

	public void Announce(String type, String sender, String content) {
		Message msg = new Message(type, sender, content, "All", "false", null, "null");
		for (int i = 0; i < clientCount; i++) {
			clients[i].send(msg);
		}
	}

	public void SendUserList(String toWhom) {
		for (int i = 0; i < clientCount; i++) {
			findUserThread(toWhom)
					.send(new Message("newuser", "SERVER", clients[i].username, toWhom, "false", null, "null"));
		}
	}

	public ServerThread findUserThread(String usr) {
		for (int i = 0; i < clientCount; i++) {
			if (clients[i].username.equals(usr)) {
				return clients[i];
			}
		}
		return null;
	}

	@SuppressWarnings("deprecation")
	public synchronized void remove(int ID) {
		int pos = findClient(ID);
		if (pos >= 0) {
			ServerThread toTerminate = clients[pos];
			ui.jTextArea1.append("\nRemoving client thread " + ID + " at " + pos);
			if (pos < clientCount - 1) {
				for (int i = pos + 1; i < clientCount; i++) {
					clients[i - 1] = clients[i];
				}
			}
			clientCount--;
			try {
				toTerminate.close();
			} catch (IOException ioe) {
				ui.jTextArea1.append("\nError closing thread: " + ioe);
			}
			toTerminate.stop();
		}
	}

	private void addThread(Socket socket) {
		if (clientCount < clients.length) {
			ui.jTextArea1.append("\nClient accepted: " + socket);
			clients[clientCount] = new ServerThread(this, socket);
			try {
				clients[clientCount].open();
				clients[clientCount].start();
				clientCount++;
			} catch (IOException ioe) {
				ui.jTextArea1.append("\nError opening thread: " + ioe);
			}
		} else {
			ui.jTextArea1.append("\nClient refused: maximum " + clients.length + " reached.");
		}
	}

	/////////////////////////////////////// DH
	/////////////////////////////////////// methods/////////////////////////////////////////////////////

	public void generateKeys() {

		try {
			final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
			keyPairGenerator.initialize(1024);

			final KeyPair keyPair = keyPairGenerator.generateKeyPair();

			privateKey = keyPair.getPrivate();
			publicKey = keyPair.getPublic();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void generateCommonSecretKey() {

		try {
			final KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
			keyAgreement.init(privateKey);
			keyAgreement.doPhase(receivedPublicKey, true);

			secretKey = shortenSecretKey(keyAgreement.generateSecret());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private byte[] shortenSecretKey(final byte[] longKey) {

		try {

			// Use 8 bytes (64 bits) for DES, 6 bytes (48 bits) for Blowfish
			final byte[] shortenedKey = new byte[12];

			System.arraycopy(longKey, 0, shortenedKey, 0, shortenedKey.length);

			return shortenedKey;

			// Below lines can be more secure
			// final SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DES");
			// final DESKeySpec desSpec = new DESKeySpec(longKey);
			//
			// return keyFactory.generateSecret(desSpec).getEncoded();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	/////////////////////////////////////// end of DH methods
	/////////////////////////////////////// /////////////////////////////////////////////////////

	// Sample method to construct a JWT
	private String createJWT(String username, String secret) throws UnsupportedEncodingException {
		// The JWT signature algorithm we will be using to sign the token
		SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
		String jwt = Jwts.builder().claim("username", username)
				.signWith(signatureAlgorithm, secret.getBytes("UTF-8")).compact();
		System.out.println("JWTTT: " + jwt);
		return jwt;
	}

}
