package com.socket;

import com.ui.ChatFrame;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;

import java.io.*;
import java.net.*;
import java.util.Date;
import java.util.Formatter;
import java.util.HashMap;

import javax.swing.JFileChooser;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableModel;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.KeyAgreement;

public class SocketClient implements Runnable {

	public int port;
	public String serverAddr;
	public Socket socket;
	public ChatFrame ui;
	public ObjectInputStream In;
	public ObjectOutputStream Out;
	public History hist;
	private Cipher cipher;
	private byte[] cipherBytes;
	public HashMap<String, String> hashMap = new HashMap<String, String>();

	//////////////////////////////////// DH
	//////////////////////////////////// attributes/////////////////////////////////////
	// ----> to be returned to default after the Hmac and AES used
	//////////////////////////////////// //////////////////////

	PrivateKey privateKey;
	public PublicKey publicKey;
	public PublicKey receivedPublicKey;
	byte[] secretKey;

	String username = "";

////////////////////////////////////AES attributes/////////////////////////////////////

	static String IV = "RandomInitVector";

////////////////////////////////////HMAC attributes/////////////////////////////////////   
	private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

////////////////////////////////////end of added attributes/////////////////////////////////////

	public SocketClient(ChatFrame frame) throws IOException {
		ui = frame;
		this.serverAddr = ui.serverAddr;
		this.port = ui.port;
		socket = new Socket(InetAddress.getByName(serverAddr), port);

		Out = new ObjectOutputStream(socket.getOutputStream());
		Out.flush();
		In = new ObjectInputStream(socket.getInputStream());

		hist = ui.hist;
	}

	@Override
	public void run() {
		boolean keepRunning = true;
		while (keepRunning) {
			try {
				Message msg = (Message) In.readObject();
				System.out.println("Incoming : " + msg.toString());


				if (msg.type.equals("message")) {


					// receiver of original message
					if (msg.dh.equals("true") && !msg.pmKey.equals(publicKey)) {
						System.out.println("this is the Dh message");
						receivedPublicKey = msg.pmKey;
						generateKeys();
						System.out.println("el fate7a");
						send(new Message("message", msg.recipient, "DH message2", msg.sender, "truereply", publicKey,
								"not Hmac"));
						// we now have our private key and the senders public key so we can start
						// calculating the DH symmetric key
						generateCommonSecretKey();
						System.out.println("this is the secret key----->" + new String(secretKey));
						// System.out.println("privatekey is ---->"+ privateKey +"\n"+ "public key is
						// ---->" + publicKey +"\n"+ "receiver's pbkey ---->"+ receivedPublicKey);

						// receiver of reply
					} else if (msg.dh.equals("truereply")) {
						if (!msg.pmKey.equals(publicKey)) {
							System.out.println("truereply----->" + msg.pmKey);
							receivedPublicKey = msg.pmKey;
							generateCommonSecretKey();
							// AES encryption
							System.out.println("this is the secret key byte array----->" + new String(secretKey));
							// trial
							String target = ui.jList1.getSelectedValue().toString();
							String base64key = new String(Base64.encodeBase64(secretKey));
							System.out.println(
									"encryption key----->" + base64key + "<--- of length---> " + base64key.length());
							Encryptor e = new Encryptor("en", base64key, IV, ui.jTextField4.getText());
							String enMsg = e.getText();
							// Hmac creation
							String s = new String(secretKey);
							String Hmac = calculateRFC2104HMAC(ui.jTextField4.getText(), s);
							msg.HMAC = Hmac;
							// emptying the Jtext4
							ui.jTextField4.setText("");
							send(new Message("message", username, enMsg, target, "false", publicKey, Hmac));
						}
//                	if(msg.pmKey.equals(publicKey)){
// 
//                		String target = ui.jList1.getSelectedValue().toString();
//                		String base64key = new String(Base64.encodeBase64(secretKey));
//                		System.out.println("encryption key----->"+base64key+"<--- of length---> "+base64key.length());
//                		Encryptor e = new Encryptor("en", base64key, IV, msg.content);
//                		String enMsg = e.getText();
//                		send(new Message("message", ui.username, enMsg, target,"false",publicKey));
//                	}

						// client.send(new Message("message", username, msg, target,"false",null));
					} else if (msg.recipient.equals(ui.username) && msg.dh == "false") {
						ui.jTextArea1.append("[" + msg.sender + " > Me] : " + msg.content + "\n");
					} else {
						if (!msg.content.equals("DH message1") && !msg.content.equals("DH message2")) {
							// resolving AES decryption
							// System.out.println("secret key used for devryption---->"+new
							// String(secretKey));
							System.out.println("the message content---->" + msg.content);
							String base64key = new String(Base64.encodeBase64(secretKey));
							System.out.println(
									"decryption key----->" + base64key + "<--- of length---> " + base64key.length());
							Encryptor e = new Encryptor("de", base64key, IV, msg.content);
							String deMsg = e.getText();
							// Hmac checker
							String s = new String(secretKey);
							String Hmacresult = calculateRFC2104HMAC(deMsg, s);
							if (msg.HMAC.equals(Hmacresult)) {
								System.out.println("The Hmac checked out----> Go norhyyyyyyy");
								String newMessage = null;
								System.out.println("Here 1");
								if (hashMap.containsKey(msg.sender + "-" + msg.recipient)) {
									System.out.println("Here 2");
									newMessage = hashMap.get(msg.sender + "-" + msg.recipient);
									newMessage += "[" + msg.sender + " > " + msg.recipient + "] : " + deMsg + "\n";
									hashMap.put(msg.sender + "-" + msg.recipient,newMessage);
								} else if (hashMap.containsKey(msg.recipient + "-" + msg.sender)) {
									System.out.println("Here 3");
									newMessage = hashMap.get(msg.recipient + "-" + msg.sender);
									newMessage += "[" + msg.sender + " > " + msg.recipient + "] : " + deMsg + "\n";
									hashMap.put(msg.recipient + "-" + msg.sender,newMessage);
								} else {
									newMessage = "[" + msg.sender + " > " + msg.recipient + "] : " + deMsg + "\n";
									hashMap.put(msg.sender + "-" + msg.recipient,newMessage);
								}

								ui.jTextArea1.setText(newMessage);
//								append("[" + msg.sender + " > " + msg.recipient + "] : " + deMsg + "\n");
								privateKey = null;
								secretKey = null;
								System.out.println("the nulls---> private =" + privateKey + "secret= " + secretKey);
							} else {
								System.out.println("The Hmac didn't check out----> RUN norhyyyyyyy");
								ui.jTextArea1.append("[" + msg.sender + " > " + msg.recipient + "] : "
										+ "your Message integrity was compromised please send again" + "\n");
								privateKey = null;
								secretKey = null;
								System.out.println("the nulls---> private =" + privateKey + "secret= " + secretKey);
							}

						}
					}

					if (!msg.content.equals(".bye") && !msg.sender.equals(ui.username)) {
						String msgTime = (new Date()).toString();

						try {
							hist.addMessage(msg, msgTime);
							DefaultTableModel table = (DefaultTableModel) ui.historyFrame.jTable1.getModel();
							table.addRow(new Object[] { msg.sender, msg.content, "Me", msgTime });
						} catch (Exception ex) {
						}
					}
				} else if (msg.type.equals("encryptpassword")) {

					receivedPublicKey = msg.pmKey;
					generateCommonSecretKey();
					System.out.println("client side secret key------>" + new String(secretKey));
					//////////////////////
					String username = ui.jTextField3.getText();
					String password = ui.jPasswordField1.getText();
					String base64key = new String(Base64.encodeBase64(secretKey));
					Encryptor e = new Encryptor("en", base64key, IV, password);
					String EnPassword = e.getText();
					send(new Message("signup", username, EnPassword, "SERVER", "false", null, "not Hmac"));

				} else if (msg.type.equals("encryptpasswordlogin")) {

					receivedPublicKey = msg.pmKey;
					generateCommonSecretKey();
					System.out.println("client side secret key------>" + new String(secretKey));
					//////////////////////
					String username = ui.jTextField3.getText();
					String password = ui.jPasswordField1.getText();
					String base64key = new String(Base64.encodeBase64(secretKey));
					Encryptor e = new Encryptor("en", base64key, IV, password);
					String EnPassword = e.getText();
					send(new Message("login", username, EnPassword, "SERVER", "false", null, "not Hmac"));

				} else if (msg.type.equals("login")) {
					if (msg.content.equals("TRUE")) {
						username = ParseJWT(msg.recipient);
						ui.jButton2.setEnabled(false);
						ui.jButton3.setEnabled(false);
						ui.jButton4.setEnabled(true);
						ui.jButton5.setEnabled(true);
						ui.jTextArea1.append("[SERVER > Me] : Login Successful\n");
						ui.jTextField3.setEnabled(false);
						ui.jPasswordField1.setEnabled(false);
						ui.jList1.addListSelectionListener(listSelectionListener);
					} else {
						ui.jTextArea1.append("[SERVER > Me] : Login Failed\n");
					}
				} else if (msg.type.equals("test")) {
					ui.jButton1.setEnabled(false);
					ui.jButton2.setEnabled(true);
					ui.jButton3.setEnabled(true);
					ui.jTextField3.setEnabled(true);
					ui.jPasswordField1.setEnabled(true);
					ui.jTextField1.setEditable(false);
					ui.jTextField2.setEditable(false);
					ui.jButton7.setEnabled(true);
				} else if (msg.type.equals("newuser")) {
					if (!msg.content.equals(ui.username)) {
						boolean exists = false;
						for (int i = 0; i < ui.model.getSize(); i++) {
							if (ui.model.getElementAt(i).equals(msg.content)) {
								exists = true;
								break;
							}
						}
						if (!exists) {
							ui.model.addElement(msg.content);
						}
					}
				} else if (msg.type.equals("signup")) {
					if (msg.content.equals("TRUE")) {
						ui.jButton2.setEnabled(false);
						ui.jButton3.setEnabled(false);
						ui.jButton4.setEnabled(true);
						ui.jButton5.setEnabled(true);
						ui.jTextArea1.append("[SERVER > Me] : Singup Successful\n");
					} else {
						ui.jTextArea1.append("[SERVER > Me] : Signup Failed\n");
					}
				} else if (msg.type.equals("signout")) {
					if (msg.content.equals(ui.username)) {
						ui.jTextArea1.append("[" + msg.sender + " > Me] : Bye\n");
						ui.jButton1.setEnabled(true);
						ui.jButton4.setEnabled(false);
						ui.jTextField1.setEditable(true);
						ui.jTextField2.setEditable(true);

						for (int i = 1; i < ui.model.size(); i++) {
							ui.model.removeElementAt(i);
						}

						ui.clientThread.stop();
					} else {
						if (!msg.content.equals("DH message1") || !msg.content.equals("DH message2")) {
							ui.model.removeElement(msg.content);
							ui.jTextArea1.append("[" + msg.sender + " > All] : " + msg.content + " has signed out\n");
						}
					}
				} else if (msg.type.equals("upload_req")) {

					if (JOptionPane.showConfirmDialog(ui,
							("Accept '" + msg.content + "' from " + msg.sender + " ?")) == 0) {

						JFileChooser jf = new JFileChooser();
						jf.setSelectedFile(new File(msg.content));
						int returnVal = jf.showSaveDialog(ui);

						String saveTo = jf.getSelectedFile().getPath();
						if (saveTo != null && returnVal == JFileChooser.APPROVE_OPTION) {
							Download dwn = new Download(saveTo, ui);
							Thread t = new Thread(dwn);
							t.start();
							// send(new Message("upload_res",
							// (""+InetAddress.getLocalHost().getHostAddress()), (""+dwn.port),
							// msg.sender));
							send(new Message("upload_res", ui.username, ("" + dwn.port), msg.sender, "false", null,
									"not Hmac"));
						} else {
							send(new Message("upload_res", ui.username, "NO", msg.sender, "false", null, "not Hmac"));
						}
					} else {
						send(new Message("upload_res", ui.username, "NO", msg.sender, "false", null, "not Hmac"));
					}
				} else if (msg.type.equals("upload_res")) {
					if (!msg.content.equals("NO")) {
						int port = Integer.parseInt(msg.content);
						String addr = msg.sender;

						ui.jButton5.setEnabled(false);
						ui.jButton6.setEnabled(false);
						Upload upl = new Upload(addr, port, ui.file, ui);
						Thread t = new Thread(upl);
						t.start();
					} else {
						ui.jTextArea1.append("[SERVER > Me] : " + msg.sender + " rejected file request\n");
					}
				} else {
					ui.jTextArea1.append("[SERVER > Me] : Unknown message type\n");
				}
			} catch (Exception ex) {
				ex.printStackTrace();
				keepRunning = false;
				ui.jTextArea1.append("[Application > Me] : Connection Failure\n");
				ui.jButton1.setEnabled(true);
				ui.jTextField1.setEditable(true);
				ui.jTextField2.setEditable(true);
				ui.jButton4.setEnabled(false);
				ui.jButton5.setEnabled(false);
				ui.jButton5.setEnabled(false);

				for (int i = 1; i < ui.model.size(); i++) {
					ui.model.removeElementAt(i);
				}

				ui.clientThread.stop();

				System.out.println("Exception SocketClient run()");
				ex.printStackTrace();
			}
		}
	}

	public void send(Message msg) {
		try {

			Out.writeObject(msg);
			Out.flush();

			if (msg.type.equals("message") || msg.type.equals("DHinit") && !msg.content.equals(".bye")) {
				System.out.println("Outgoing : " + msg.toString());
				String msgTime = (new Date()).toString();
				try {
					hist.addMessage(msg, msgTime);
					DefaultTableModel table = (DefaultTableModel) ui.historyFrame.jTable1.getModel();
					table.addRow(new Object[] { "Me", msg.content, msg.recipient, msgTime, msg.dh });
				} catch (Exception ex) {
				}
			}
		} catch (IOException ex) {
			System.out.println("Exception SocketClient send()");
		}

	}

	public void closeThread(Thread t) {
		t = null;
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

	/////////////////////////////////////// AES
	/////////////////////////////////////// /////////////////////////////////////////////////////

	public String encrypt(String key, String initVector, String value) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

			byte[] encrypted = cipher.doFinal(value.getBytes());
			System.out.println("encrypted string: " + Base64.encodeBase64String(encrypted));

			return Base64.encodeBase64String(encrypted);
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}

	public String decrypt(String key, String initVector, String encrypted) {
		try {
			IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
			SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

			byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));

			return new String(original);
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}
	
    ListSelectionListener listSelectionListener = new ListSelectionListener() {
        public void valueChanged(ListSelectionEvent listSelectionEvent) {
			String defaultPage = null;
			if (ui.jList1.getSelectedValue() != null) {
				String targetUser = ui.jList1.getSelectedValue().toString();
				if (targetUser != null && username != "") {
					if (hashMap.containsKey(username + "-" + targetUser)) {
						defaultPage = hashMap.get(username + "-" + targetUser);
						System.out.println(username + "-" + targetUser);
						System.out.println("Default Page ------" + defaultPage);
					} else if (hashMap.containsKey(targetUser + "-" + username)) {
						defaultPage = hashMap.get(targetUser + "-" + username);
						System.out.println(targetUser + "-" + username);
						System.out.println("Default Page ------" + defaultPage);
					} else {
						defaultPage = "";
						System.out.println(targetUser + "-" + username);
					}

					ui.jTextArea1.setText(defaultPage);
				} else {
					ui.jTextArea1.setText("");
				}
			}
        }
      };

	//////////////////////////////////////// HMAC
	//////////////////////////////////////// Methods///////////////////////////////////////////////////

	private static String toHexString(byte[] bytes) {
		Formatter formatter = new Formatter();

		for (byte b : bytes) {
			formatter.format("%02x", b);
		}

		return formatter.toString();
	}

	public static String calculateRFC2104HMAC(String data, String key)
			throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
		SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
		Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
		mac.init(signingKey);
		return toHexString(mac.doFinal(data.getBytes()));
	}

	/////////////////////////////////////// methods end
	/////////////////////////////////////// /////////////////////////////////////////////////////

	private String ParseJWT(String jwt) throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException,
			SignatureException, IllegalArgumentException, UnsupportedEncodingException {
		String secret = "secret";
		Jws<Claims> claims = Jwts.parser().setSigningKey(secret.getBytes("UTF-8")).parseClaimsJws(jwt);
		System.out.println(claims.getSignature());
		System.out.println(claims.getBody().get("username"));
		return (String) claims.getBody().get("username");
	}
}
