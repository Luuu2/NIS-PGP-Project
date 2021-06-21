package ChatClient;

import java.awt.image.BufferedImage;
import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import static java.nio.charset.StandardCharsets.UTF_8;
import java.util.Base64.Decoder;
import java.util.Scanner;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Client {
    private static final String BC_PROVIDER = "BC";
    private final String serverName;
    private final int serverPort;
    private OutputStream serverOut;
    private InputStream serverIn;
    private BufferedReader bufferIn;
    private final String userName;
    private final String password;
    private Socket socket;
    private Scanner scanner;
    private DataInputStream dis;
    private ObjectInputStream ois;
    private String cipher;
    private SecretKey key;
    private IvParameterSpec iv;
    String receiver;
    String sender;
    private Certificate certificate;
    private Certificate rootCertificate;
    private PrivateKey privateKey;

    public Client(String serverName, int serverPort, String userName, String password) {
        this.serverName = serverName;
        this.serverPort = serverPort;
        this.userName = userName;
        this.password = password;

        try{       
            String certfile = userName.equalsIgnoreCase("Bob") ? "PGP-iBcert.cer":"PGP-iAcert.cer";
            String alias = userName.equalsIgnoreCase("Bob") ? "PGP-iBcert":"PGP-iAcert";
            String ksfile = userName.equalsIgnoreCase("Bob") ? "PGP-iBcert.pfx":"PGP-iAcert.pfx"; 
            importKeyPairFromKeystoreFile(ksfile, certfile, alias, "PKCS12");

        }catch( Exception e ){
            System.out.print("Error Import");
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws ClassNotFoundException {
        Client client = new Client("localhost", 8818, args[0], args[1]);
        if (client.connect()) {
        Security.addProvider(new BouncyCastleProvider());
            System.out.println("Connect successful.");
            try {
                client.login();
            } catch (IOException e) {
                e.printStackTrace();
                System.out.println("Error logging in");
            }
        } else {
            System.out.println("Connect failed.");
        }
    }

    private void importKeyPairFromKeystoreFile(String fileNameKS, String fileNameC, String alias, String storeType) throws Exception {
        FileInputStream keyStoreOs;
        FileInputStream userCert;
        FileInputStream rootCert;
        try{
            keyStoreOs = new FileInputStream(fileNameKS);
            userCert = new FileInputStream(fileNameC);
            rootCert = new FileInputStream("PGP-rcert.cer");

            System.out.println(keyStoreOs);
            System.out.println(userCert);
            KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);
            System.out.print("Keystore check: ");
            System.out.println(sslKeyStore);

            char[] keyPassword = password.toCharArray();
            sslKeyStore.load(keyStoreOs, keyPassword);
            System.out.print("Alias check: ");
            System.out.println(alias);

            KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyPassword);
            //System.out.print("Password check: ");
            //System.out.println(entryPassword);

            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)
            sslKeyStore.getEntry(alias, entryPassword);
            this.privateKey = privateKeyEntry.getPrivateKey();

            // GET CERT
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BC_PROVIDER);
            System.out.println("\nCertification Factory Check");
            System.out.println( cf );
            
            System.out.println("Certification Check");
            BufferedInputStream bisCert = new BufferedInputStream(userCert);
            
            while (bisCert.available() > 0) {
                System.out.println("User Cert");
                //System.out.println(bisCert);
                this.certificate = cf.generateCertificate(bisCert);
                System.out.println(certificate.toString());
            }

            System.out.println("Root Certification Check");
            BufferedInputStream bisCertR = new BufferedInputStream(rootCert);
            while (bisCertR.available() > 0) {
                System.out.println("Root Cert");
                //System.out.println(bisCertR);
                this.rootCertificate = cf.generateCertificate(bisCertR);
                System.out.println(rootCertificate.toString());
            }

            userCert.close();
            rootCert.close();
        } catch(Exception e){
            System.out.println("Kubird!");
            e.printStackTrace();
        }
    }

    public boolean connect(){
        try{
            this.socket = new Socket(serverName, serverPort);
            System.out.println("Connected to server");
            this.serverOut = socket.getOutputStream();
            this.serverIn = socket.getInputStream();
            this.dis = new DataInputStream(serverIn);
            this.ois = new ObjectInputStream(socket.getInputStream());
            this.bufferIn = new BufferedReader(new InputStreamReader(serverIn));
            this.scanner = new Scanner(System.in);
            return true;

        } catch (Exception e) {
            System.out.println("Unable to connect");
            e.printStackTrace();
        }
        return false;
    }

    private boolean login() throws IOException, ClassNotFoundException {
        // Certificaition Step
        try{
            handleCertification();
        } catch (InterruptedException e){
            e.printStackTrace();
        }
        // Certificaition Step
        String cmd = "login "+ userName + " "+ password+"\n";
        serverOut.write(cmd.getBytes());
        String response = bufferIn.readLine();
        System.out.println("Response Line: " + response);
        if ("ok login".equalsIgnoreCase(response)) {
            getKey();
            //this.key = getKey();
            System.out.println("got key");
            System.out.println(key);
            getIv();
            System.out.println("got iv");
            System.out.println(iv);
            msgReader();
            msgWriter();
            return true;
        } else {
            return false;
        }
    }

    //should be verifying the other client's certificate not the server's 
    private void handleCertification() throws IOException, InterruptedException{
        System.out.println("Sending certificate to Server");
        InputStream input = this.serverIn;
        OutputStream output = this.serverOut;

        //////////////////////////////////////
        /**
         * Sending user the server X509 certificate 
        **/
        // Convert CERT into byte[]
        byte[] certificateBytes = null;
        try{
            System.out.println(certificate);
            certificateBytes = certificate.getEncoded();
        } catch( CertificateEncodingException e ){
            System.out.println("Certificate Encoding Exception error");
            e.printStackTrace();
        } catch( Exception e ){
            System.out.println("I don't know");
            e.printStackTrace();
        }
        
        if(certificateBytes == null){
            System.out.println("Not Sending Certificate Bytes");
        }else {
            System.out.println("Sending Certificate Bytes");
            output.write( certificateBytes );
        }

        //////////////////////////////////////////
        CertificateFactory certFactory = null;                        
        Certificate cert = null; // server certificate

        /**
         * Verifying server the X509 certificate 
        **/
        try{
            BufferedInputStream bis = new BufferedInputStream(input);
            System.out.print("Check Server Certificate: ");
            System.out.println(cert);
            certFactory = CertificateFactory.getInstance("X.509");
                
            cert = certFactory.generateCertificate(bis);
            System.out.println(cert);
            System.out.println("X.509 Certificate Constructed");
        }catch( CertificateException e ){
            System.out.println("X.509 Certificate Not Constructed");
            e.printStackTrace();
        } 

        /**
         * Verifying server the X509 certificate 
        **/
        try {
            System.out.println("Verification of User Certificate");
            cert.verify(rootCertificate.getPublicKey(), Security.getProvider(BC_PROVIDER)); 
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException e) {
            //handle wrong algos
            System.out.print("handle wrong algorithms");
        } catch (SignatureException ex) {
            //signature validation error
            System.out.print("signature validation error");
        }

    }

    private void msgReader(){
        Thread t = new Thread(){
            public void run(){
                while(true){
                    try {
                        String response = bufferIn.readLine();
                        String[] tokens = response.split(" ", 3);
                        // tokens[0] == msg keyword for server, tokens[2] == message body
                        if (userName.equalsIgnoreCase("Alice")) {
                            sender = "Bob";
                        } else {
                            sender = "Alice";
                        }
                        if (tokens[0].equalsIgnoreCase("online")) {
                            // System.out.println("inside condition 1");
                            System.out.println(sender + " is online\n");
                        } else if (tokens[0].equalsIgnoreCase("Offline")) {
                            System.out.println(sender + " logged off\n");
                        } else if (tokens[0].equalsIgnoreCase("msg")) {
                            System.out.println(sender + ": " + tokens[2] + "\n");
                        } else if (tokens[0].equalsIgnoreCase("img")) {
                            // System.out.println(sender + ": " + tokens[2] + "\n");
                            try {
                                // System.out.println("");
                                //String captionFile = new String(tokens[2]); // "caption space base64Image"
                                
                                String [] div =tokens[2].split(" ", 2);
                                //System.out.println(div[1]);
                                //cipher = ci.getBytes();
                                String plainText = decrypt("AES/CBC/PKCS5Padding", div[0] , key, iv);
                                String [] imgCap = plainText.split(" ",2);
                                decodeString(imgCap);
                               // decodeString(captionFile.split(" ")); // new list format: [caption, base64Image]
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                        else if(tokens[0].equalsIgnoreCase("Offline")){
                            System.out.println(sender +" logged off\n");
                        }
                        else if(tokens[0].equalsIgnoreCase("msg")){
                            System.out.println(sender +": "+tokens[2]+"\n");
                        }
                        else if(tokens[0].equalsIgnoreCase("img")){
                            System.out.println(sender +": "+tokens[2]+"\n");
                        }
                        else {
                            System.out.println(response+"\n");
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                        break;
                    }

                }
            }
        };
        t.start();
    }

    private void msgWriter() {
        if (userName.equalsIgnoreCase("Alice")) {
            receiver = "Bob";
        } else {
            receiver = "Alice";
        }
        Thread t = new Thread() {
            public void run() {
                boolean online = true;
                while (online == true) {
                    String message = scanner.nextLine();
                    String [] tokens = message.split(" ", 3);
                    if(message.equalsIgnoreCase("quit") || message.equalsIgnoreCase("logoff")){
                        String cmd = "quit";
                        try {
                            serverOut.write(cmd.getBytes());
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        break;
                    } else if (tokens[0].equalsIgnoreCase("img")) {
                        try {
                            cipher = encrypt("AES/CBC/PKCS5Padding", encodeString(tokens, receiver), key, iv);
                            System.out.println(cipher);
                            String cmd = "img" +" "+ receiver + " " + cipher + "\n";
                            System.out.println("writing to server");
                            serverOut.write(cmd.getBytes());
                            System.out.println("wrote to server");

                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        String cmd = "msg " + receiver + " " + message + "\n";
                        try {
                            System.out.println ("somehow we are here");
                            serverOut.write(cmd.getBytes());
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        };
        t.start();
    }

    private void getKey() throws ClassNotFoundException, IOException {
       
            ois = new ObjectInputStream(new FileInputStream("../ChatServer/Key.txt"));
            key = (SecretKey) ois.readObject();
            ois.close();
            //byte [] encoded
            //key = new SecretKeySpec(dis.readAllBytes(), "AES");
            //key = (SecretKey) ois.readObject();

       
        //return key;
    }

    private void getIv() throws FileNotFoundException, IOException, ClassNotFoundException {
        byte [] b = new byte[16];
        dis = new DataInputStream(new FileInputStream(new File("../ChatServer/IV.txt")));
        dis.readFully(b);
        iv= new IvParameterSpec(b);
        dis.close();
    }

    private String encodeString(String[] tokens, String receiver) throws Exception { // tokens format: [img,caption,file]
        String caption = tokens[1];
        //System.out.println(caption);
        File f = new File("/home/kunta-kinte/Pictures/LovGrover.jpeg"); // file to be taken in (image path)
        FileInputStream fis = new FileInputStream(f); // taking in file
        System.out.println("Still sending to server....");
        byte imageData[] = new byte[(int) f.length()];
        fis.read(imageData);
        String base64Image = Base64.getEncoder().encodeToString(imageData);
        /*
         * BufferedImage bImage = ImageIO.read(new File(tokens[2]));
         * ByteArrayOutputStream bos = new ByteArrayOutputStream();
         * ImageIO.write(bImage, "jpg", bos); byte[] b = bos.toByteArray(); fis.read(b,
         * 0, b.length); // reading all bytes of file
         */
        //System.out.println("Still sending to server....");
        // String cmd = "img " + receiver + " " + Base64.getEncoder().encodeToString(b)
        // + " " + caption + "\n";
        String cmd = "img " + receiver + " " + base64Image + " " + caption + "\n";
        String encodedImgCap = base64Image + " " + caption;
        //serverOut.write(cmd.getBytes());
        //System.out.println("Sent to server");
        return encodedImgCap;
        // System.out.println(cmd);

    }

    // token format from server: [baseImage,caption]
    private void decodeString(String[] tokens) throws Exception { // tokens format: ["img",reciever,caption base64Image]
                                                                  // -- takes in the caption + baseimage as one
        System.out.println("Recieving from server...");
        FileOutputStream fos = new FileOutputStream("/home/kunta-kinte/Desktop/LovGrover.jpeg"); // where the new
                                                                                                    // file
                                                                                                    // will be saved
        try {
            // String captionFile = new String(tokens[2]).split(" "));
            String file = new String(tokens[0]).replaceAll(" +", "+");
            byte[] b = Base64.getDecoder().decode(file);
            System.out.println("Recieving from server...");
            // serverIn.read(b,0,b.length); //read bytes, i think it reads in what is sent
            // after the above line e.g "hi" hence reads nothing into the file
            fos.write(b); // write bytes to new file
            System.out.println("Received!");
            System.out.println(sender +" " +"sent an image with the caption "+tokens[1]);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // encryting Base64 + caption String
    public static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes(UTF_8));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    // decrypting Base64 + caption String
    public static String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        Decoder decoder = Base64.getMimeDecoder();
        byte[] bytes = decoder.decode(cipherText.getBytes(UTF_8));
        String decodedString = new String(bytes, UTF_8);
        byte [] input = decodedString.getBytes(UTF_8);
        byte[] plainText = cipher.doFinal(bytes);
        return new String(plainText);
    }

    // Lulu encde string method --- this has been implemented with the encodeString
    // method
    /*
     * private String encodeFileToBase64Binary(File file) { String encodedfile =
     * null; try { FileInputStream fileInputStreamReader = new
     * FileInputStream(file); byte[] bytes = new byte[(int) file.length()];
     * fileInputStreamReader.read(bytes); encodedfile =
     * Base64.getEncoder().encodeToString(bytes); fileInputStreamReader.close(); }
     * catch (FileNotFoundException e) { // TODO Auto-generated catch block
     * e.printStackTrace(); } catch (IOException e) { // TODO Auto-generated catch
     * block e.printStackTrace(); }
     * 
     * return encodedfile; }
     */

}

/*
 * public class Client { private final String serverName; private final int
 * serverPort; private OutputStream serverOut; private Socket socket; private
 * InputStream serverIn; private BufferedReader bufferIn;
 * 
 * private ArrayList<UserStatusListener> listeners = new ArrayList<>(); private
 * ArrayList<MessageListener> messages = new ArrayList<>();
 * 
 * public Client(String serverName, int serverPort){ this.serverName =
 * serverName; this.serverPort = serverPort; }
 * 
 * public static void main(String [] args) throws IOException { Client client =
 * new Client("localhost", 8818);
 * 
 * client.addListener(new UserStatusListener(){
 * 
 * @Override public void online(String login) {
 * System.out.println("Online: "+login);
 * 
 * }
 * 
 * @Override public void offline(String login) {
 * System.out.println("Offline: "+login); }
 * 
 * });
 * 
 * client.addMessageListeners(new MessageListener(){
 * 
 * @Override public void onMessage(String fromLogin, String msgBody) {
 * System.out.println("You have a message from "+ fromLogin);
 * System.out.println("Message: "+ msgBody);
 * 
 * }
 * 
 * });
 * 
 * if(!client.connect()){ System.err.println("Connect failed."); } else{
 * System.out.println("Connect successful.");
 * 
 * if(client.login("guest", "guest")){ System.out.println("Login Successful");
 * client.msg("jim", "Hello World"); } else{ System.out.println("Login Failed");
 * }
 * 
 * //client.logOff();
 * 
 * } }
 * 
 * private void msg(String sendto, String msgbody) throws IOException { String
 * cmd = "msg " + sendto + " "+ msgbody +"\n"; serverOut.write(cmd.getBytes());
 * }
 * 
 * private void logOff() throws IOException { String cmd = "logoff\n";
 * serverOut.write(cmd.getBytes());
 * 
 * }
 * 
 * private boolean login(String userName, String password) throws IOException {
 * String cmd = "login "+ userName + " "+ password+"\n";
 * serverOut.write(cmd.getBytes()); String response = bufferIn.readLine();
 * System.out.println("Response Line: "+ response);
 * if("ok login".equalsIgnoreCase(response)){ startMessageReader(); return true;
 * } else{ return false; } }
 * 
 * private void startMessageReader() { Thread t = new Thread(){ public void
 * run(){ readMessageLoop(); } }; t.start(); }
 * 
 * protected void readMessageLoop() { try{ String line; while((line =
 * bufferIn.readLine())!=null){ String [] tokens = line.split(" ", 3);
 * if(tokens!=null & tokens.length>0){ String cmd = tokens[0]; if
 * ("online".equalsIgnoreCase(cmd)){ handleOnline(tokens); } else if
 * ("offline".equalsIgnoreCase(cmd)){ handleOffline(tokens); } else if
 * ("msg".equalsIgnoreCase(cmd)){ handleMessage(tokens); }
 * 
 * }
 * 
 * } } catch (Exception e){ e.printStackTrace(); try { socket.close(); } catch
 * (IOException e1) { e1.printStackTrace(); } } }
 * 
 * private void handleMessage(String [] tokens) { String login = tokens [1];
 * String msgBody = tokens[2];
 * 
 * for(MessageListener message : messages){ message.onMessage(login, msgBody); }
 * }
 * 
 * private void handleOffline(String[] tokens) { String login = tokens [1];
 * for(UserStatusListener listener: listeners){ listener.offline(login); } }
 * 
 * private void handleOnline(String [] tokens) { String login = tokens [1];
 * for(UserStatusListener listener: listeners){ listener.online(login); } }
 * 
 * private boolean connect() { try { this.socket = new Socket(serverName,
 * serverPort); System.out.println("Client port is "+socket.getLocalPort());
 * this.serverOut = socket.getOutputStream(); this.serverIn =
 * socket.getInputStream(); this.bufferIn = new BufferedReader(new
 * InputStreamReader(serverIn)); return true; } catch (IOException e) {
 * e.printStackTrace(); } return false; }
 * 
 * public void addListener(UserStatusListener userListener){
 * listeners.add(userListener); } public void removeListener(UserStatusListener
 * userListener){ listeners.remove(userListener); }
 * 
 * public void addMessageListeners(MessageListener message){
 * messages.add(message); }
 * 
 * public void removeMessageListeners(MessageListener message){
 * messages.remove(message); } }
 */
// Assume that server is already authenticated and known to client 
// From the sever we need to get the other client's certificate to verify customer as trustworthy
// Thus certify othe client's certificate not server's certificate
// Keep the CA server certificate as a trusted certificate. 