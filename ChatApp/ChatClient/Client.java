package ChatClient;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Scanner;

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
import java.nio.charset.StandardCharsets;

import java.net.Socket;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.awt.image.BufferedImage;
import javax.imageio.ImageIO;


public class Client {
    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    private final String serverName;
    private final String userName;
    private final String password;
    private final int serverPort;

    private BufferedReader bufferIn;
    private DataInputStream dis;
    private ObjectInputStream ois;
    private OutputStream serverOut;
    private InputStream serverIn;
    private Socket socket;
    private Scanner scanner;

    private SecretKey key;
    private IvParameterSpec iv;

    private String cipher;
    private String receiver;
    private String sender;

    private Certificate certificate;
    private Certificate rootCertificate;
    private PrivateKey privateKey;

    public Client(String serverName, int serverPort, String userName, String password) {
        this.serverName = serverName;
        this.serverPort = serverPort;
        this.userName = userName;
        this.password = password;

        String alias = userName.equalsIgnoreCase("Bob") ? "PGP-iBcert":"PGP-iAcert";
        String certfile = alias + ".cer";
        String ksfile = alias + ".pfx"; 

        try{ 
            importKeyPairFromKeystoreFile(ksfile, certfile, alias, "PKCS12");
        }catch( Exception e ){
            System.out.print("Error In Importing Key Pair From Keystore File");
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws ClassNotFoundException {
        Security.addProvider(new BouncyCastleProvider());
        Client client = new Client("localhost", 8818, args[0], args[1]);
        if (client.connect()) {
            System.out.println("Connect successful.");
            try{
                if (!client.login()) throw new IOException();
            }catch (IOException e) {
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
            System.out.print("Certificates Files Present check: ");
            keyStoreOs = new FileInputStream(fileNameKS);
            //System.out.println(keyStoreOs);
            userCert = new FileInputStream(fileNameC);
            ///System.out.println(userCert);
            rootCert = new FileInputStream("PGP-rcert.cer");
            System.out.println("complete\n");

            ////////////////////////////////////////////////////////

            System.out.print("Keystore Accepted and Loaded: ");
            KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);
            char[] keyPassword = password.toCharArray();

            sslKeyStore.load(keyStoreOs, keyPassword);
            KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyPassword);
            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)
                sslKeyStore.getEntry(alias, entryPassword);
            this.privateKey = privateKeyEntry.getPrivateKey();
            System.out.println( (sslKeyStore != null) + "\n" );

            ///////////////////////////////////////////

            // Get Certificates
            System.out.println("Get Root and" + this.userName + "\'s Certificate");
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BC_PROVIDER);

            System.out.print("User Certificate Present: ");
            this.certificate = privateKeyEntry.getCertificate();
            System.out.println(certificate != null);

            BufferedInputStream bisCertR = new BufferedInputStream(rootCert);
            while (bisCertR.available() > 0) {
                System.out.print("Root Certificate Present: ");
                this.rootCertificate = cf.generateCertificate(bisCertR);
                System.out.println(rootCertificate != null);
            }
            rootCert.close();
            System.out.print("Certificates Retrieved");

        }catch(FileNotFoundException e){
            System.out.println("\nFile Input Stream Error");
            //e.printStackTrace();
            System.out.println("Exiting Program...");
            System.exit(0);
        }catch(Exception e){
            System.out.println("\nLogin Details Incorrect.");
            //e.printStackTrace();
            System.exit(0);
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

        }catch (Exception e) {
            System.out.println("Unable to connect");
            e.printStackTrace();
        }
        return false;
    }

    private boolean login() throws IOException, ClassNotFoundException {
        // Certificaition Step
        System.out.println("Certification Step - Beginning");
        boolean loginUser = false;
        try{
            loginUser = handleCertification();
        }catch (InterruptedException e){
            e.printStackTrace();
        }
        // If Handle Certification Failed for whatever reason return false
        if(!loginUser){
            System.out.println("Certification Step - Failed");
            return loginUser;
        }
        System.out.println("Certification Step - Complete");
        // Certificaition Step - END

        String cmd = "login "+ userName + " "+ password+"\n";
        serverOut.write(cmd.getBytes());
        String response = bufferIn.readLine();
        System.out.println("Response Line: " + response);
        if ("ok login".equalsIgnoreCase(response)) {
            getKey();
            //this.key = getKey();
            System.out.print("Key Present: ");
            System.out.println(key != null);
            getIv();
            System.out.print("IV Present: ");
            System.out.println(iv != null);
            msgReader();
            msgWriter();
            return true;
        } else {
            return false;
        }
    }

    //should be verifying the other client's certificate and the server's
    private boolean handleCertification() throws IOException, InterruptedException{
        System.out.println("Sending certificate to Server");
        InputStream input = this.serverIn;
        OutputStream output = this.serverOut;

        /**
         * Sending user the server X509 certificate 
        **/
        // Convert CERT into byte[]
        byte[] certificateBytes = null;
        try{
            System.out.print("Certificate Present: ");
            System.out.println(certificate != null);
            certificateBytes = certificate.getEncoded();
        }catch( CertificateEncodingException e ){
            System.out.println("Certificate Encoding Exception error");
            e.printStackTrace();
        }catch( Exception e ){
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
        System.out.println("\nReceiving certificate from Server");
        Certificate cert = null; // server certificate
        /**
         * Verifying server the X509 certificate 
        **/
        try{
            BufferedInputStream bis = new BufferedInputStream(input);
            System.out.print("Server Certificate Present: ");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            cert = cf.generateCertificate(bis);
            
            System.out.println(cert != null);
            System.out.println("X.509 Certificate Constructed");
        }catch( CertificateException e ){
            System.out.println("X.509 Certificate Not Constructed");
            e.printStackTrace();
        } 

        /////////////////////////////////////////
        //Need to have verified condition in the code to client prevent 
        //continuing
        System.out.print("\nVerification of Server Certificate: ");
        /**
         * Verifying server the X509 certificate 
        **/
        try{
            cert.verify(rootCertificate.getPublicKey(), Security.getProvider(BC_PROVIDER)); 
            System.out.println("complete");
            return true;
        }catch (NoSuchAlgorithmException | InvalidKeyException e) {
            //handle wrong algos
            System.out.print("Handle wrong algorithms or Invalid key");
            e.printStackTrace();
        }catch (CertificateException e) {
            //certificate encoding error
            System.out.print("On encoding errors");
            e.printStackTrace();
        }catch (SignatureException e) {
            //signature validation error
            System.out.print("Signature validation error");
            e.printStackTrace();
        }catch (Exception e) {
            System.out.print("Other error");
            e.printStackTrace();
        }
        System.out.println("failed\n");
        return false;
    }

    private void msgReader(){
        Thread t = new Thread(){
            public void run(){
                while(true){
                    try{
                        String response = bufferIn.readLine();
                        String[] tokens = response.split(" ", 3);
                        // tokens[0] == msg keyword for server
                        // tokens[2] == message body
                        if (userName.equalsIgnoreCase("Alice")) {
                            sender = "Bob";
                        } else {
                            sender = "Alice";
                        }
                        if (tokens[0].equalsIgnoreCase("online")) {
                            System.out.println(sender + " is online\n");
                        } else if (tokens[0].equalsIgnoreCase("offline")) {
                            System.out.println(sender + " logged off\n");
                        } else if (tokens[0].equalsIgnoreCase("msg")) {
                            System.out.println(sender + ": " + tokens[2] + "\n");
                        } else if (tokens[0].equalsIgnoreCase("img")) {
                            String [] div = tokens[2].split(" ", 2);
                            try{
                                String plainText = decrypt("AES/CBC/PKCS5Padding", div[0] , key, iv);
                                String [] imgCap = plainText.split(" ",2);
                                decodeString(imgCap);
                            }catch (Exception e) {
                                e.printStackTrace();
                            }
                        }
                        else {
                            System.out.println(response+"\n");
                        }
                    }catch (IOException e) {
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
                        try{
                            serverOut.write(cmd.getBytes());
                        }catch (IOException e) {
                            e.printStackTrace();
                        }
                        break;
                    } else if (tokens[0].equalsIgnoreCase("img")) {
                        try{
                            cipher = encrypt("AES/CBC/PKCS5Padding", encodeString(tokens, receiver), key, iv);
                            System.out.println(cipher);
                            String cmd = "img" +" "+ receiver + " " + cipher + "\n";
                            System.out.println("writing to server");
                            serverOut.write(cmd.getBytes());
                            System.out.println("wrote to server");
                        }catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        String cmd = "msg " + receiver + " " + message + "\n";
                        try{
                            System.out.println ("somehow we are here");
                            serverOut.write(cmd.getBytes());
                        }catch (IOException e) {
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

        String cmd = "img " + receiver + " " + base64Image + " " + caption + "\n";
        String encodedImgCap = base64Image + " " + caption;
        return encodedImgCap;
    }

    // token format from server: [baseImage,caption]
    private void decodeString(String[] tokens) throws Exception { // tokens format: ["img",reciever,caption base64Image]
                                                                  // -- takes in the caption + baseimage as one
        System.out.println("Recieving from server...");
        FileOutputStream fos = new FileOutputStream("/home/kunta-kinte/Desktop/LovGrover.jpeg"); // where the new
                                                                                                    // file
                                                                                                    // will be saved
        try{
            String file = new String(tokens[0]).replaceAll(" +", "+");
            byte[] b = Base64.getDecoder().decode(file);
            System.out.println("Recieving from server...");
            // serverIn.read(b,0,b.length); //read bytes, i think it reads in what is sent
            // after the above line e.g "hi" hence reads nothing into the file
            fos.write(b); // write bytes to new file
            System.out.println("Received!");
            System.out.println(sender +" " +"sent an image with the caption "+tokens[1]);
        }catch (Exception e) {
            e.printStackTrace();
        }
    }

    // encryting Base64 + caption String
    public static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    // decrypting Base64 + caption String
    public static String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        Decoder decoder = Base64.getMimeDecoder();
        byte[] bytes = decoder.decode(cipherText.getBytes(StandardCharsets.UTF_8));
        byte[] plainText = cipher.doFinal(bytes);
        return new String(plainText);
    }
}

// Assume that server is already authenticated and known to client 
// From the sever we need to get the other client's certificate to verify customer as trustworthy
// Thus certify othe client's certificate not server's certificate
// Keep the CA server certificate as a trusted certificate. 