package ChatClient;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
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
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

import java.net.Socket;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.MessageDigest;
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

    private String cipherAES;
    private String cipherRSA;
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

            // Get Certificates
            System.out.print("Get Root and" + this.userName + "\'s Certificate");
            CertificateFactory cf = CertificateFactory.getInstance("X.509", BC_PROVIDER);
            
            //System.out.println("Certification Check");
            BufferedInputStream bisCert = new BufferedInputStream(userCert);
            while (bisCert.available() > 0) {
                System.out.print("User Certificate Present: ");
                this.certificate = cf.generateCertificate(bisCert);
                System.out.println(certificate != null);
            }
            userCert.close();

            //System.out.println("Root Certification Check");
            BufferedInputStream bisCertR = new BufferedInputStream(rootCert);
            while (bisCertR.available() > 0) {
                System.out.print("Root Certificate Present: ");
                this.rootCertificate = cf.generateCertificate(bisCertR);
                System.out.println(rootCertificate != null);
            }
            rootCert.close();
            System.out.print("Certificates Retrieved");

        }catch(FileNotFoundException e){
            System.out.println("File Input Stream Error");
            e.printStackTrace();
            System.out.println("Exiting Program...");
            System.exit(0);
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
            System.out.println("Show Certification");
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
                                String[] div = tokens[2].split(" ", 2);
                                String plainTextRSA = decryptRSA("RSA/ECB/PKCS1Padding", div[0]);
                                String plainTextAES = decryptAES("AES/CBC/PKCS5Padding", plainTextRSA, key, iv);
                                String decompressedData = decompress(plainTextAES);
                                String[] imgCap = decompressedData.split(" ", 2);
                                decodeString(imgCap);
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
                            cipherAES = encryptAES("AES/CBC/PKCS5Padding", encodeString(tokens, receiver), key, iv);
                            cipherRSA = encryptRSA("RSA/ECB/PKCS1Padding", cipherAES, certificate);
                            String cmd = "img" +" "+ receiver + " " + cipherRSA + "\n";
                            System.out.println("writing to server");
                            serverOut.write(cmd.getBytes());
                            System.out.println("wrote to server");

                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        String cmd = "msg " + receiver + " " + message + "\n";
                        try {
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
        File f = new File("/Users/aneledlamini/Desktop/sunset.jpg"); // file to be taken in (image path)
        FileInputStream fis = new FileInputStream(f); // taking in file
        System.out.println("Still sending to server....");
        byte imageData[] = new byte[(int) f.length()];
        fis.read(imageData);
        String base64Image = Base64.getEncoder().encodeToString(imageData);
        String hashout = sha256(base64Image + " " + caption);
        String encodedImgCap = compress(base64Image + " " + caption + " " + hashout);
        return encodedImgCap;
    }

    // token format from server: [baseImage,caption]
    private void decodeString(String[] tokens) throws Exception { // tokens format: ["img",reciever,caption base64Image]
                                                                  // -- takes in the caption + baseimage as one
        System.out.println("Recieving from server...");
        FileOutputStream fos = new FileOutputStream("/Users/aneledlamini/Desktop/NIS/sunset.jpg"); // where the new
                                                                                                    // file
                                                                                                    // will be saved
        try {
            String [] captionHash = new String(tokens[1]).split(" ",2);

            //calculating hash
            String hashin = sha256(tokens[0]+" "+captionHash[0]);
            if (captionHash[1].equalsIgnoreCase(hashin)) {
                String file = new String(tokens[0]).replaceAll(" +", "+");
                byte[] b = Base64.getDecoder().decode(file);
                System.out.println("Recieving from server...");
                fos.write(b); // write bytes to new file
                System.out.println("Received!");
                System.out.println(sender + " " + "sent an image with the caption " + captionHash[0]);
            }
            else{
                System.out.println("Confidentiality breached!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // AES decrypt + encrypt
    // encryting Base64 + caption String
    private String encryptAES(String algorithm, String input, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    // decrypting Base64 + caption String
    private String decryptAES(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        Decoder decoder = Base64.getMimeDecoder();
        byte[] bytes = decoder.decode(cipherText.getBytes(StandardCharsets.UTF_8));
        byte[] plainText = cipher.doFinal(bytes);
        return new String(plainText);
    }

    // RSA encryption + decrypting
    private String encryptRSA(String algorithm, String input, Certificate certif) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
       
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, certif.getPublicKey());
        byte[] cipherText = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(cipherText);
    }

    private String decryptRSA(String algorithm, String input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] cipherText = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(cipherText);
    }


    // hashing 
    private static String sha256(String rawinput){
        String hashout = "";
        try{
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.reset();
            digest.update(rawinput.getBytes("utf8"));
            hashout = String.format("%040x", new BigInteger(1, digest.digest()));
        }
        catch(Exception E){
            System.out.println("Hash Exception");
        }
        return hashout;
    }
    // compression
    private static String compress(String data) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream(data.length());
        GZIPOutputStream gzip = new GZIPOutputStream(bos);
        gzip.write(data.getBytes());
        gzip.close();
        byte[] compressed = bos.toByteArray();
        bos.close();
        return Base64.getEncoder().encodeToString(compressed);
    }

    private static String decompress(String st) throws IOException {
        byte[] compressed = Base64.getDecoder().decode(st);
        ByteArrayInputStream bis = new ByteArrayInputStream(compressed);
        GZIPInputStream gis = new GZIPInputStream(bis);
        BufferedReader br = new BufferedReader(new InputStreamReader(gis, "UTF-8"));
        StringBuilder sb = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            sb.append(line);
        }
        br.close();
        gis.close();
        bis.close();
        return sb.toString();
    }

}

// Assume that server is already authenticated and known to client 
// From the sever we need to get the other client's certificate to verify customer as trustworthy
// Thus certify othe client's certificate not server's certificate
// Keep the CA server certificate as a trusted certificate. 