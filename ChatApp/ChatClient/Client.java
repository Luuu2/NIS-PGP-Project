package ChatClient;

import java.util.ArrayList;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import java.util.Scanner;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
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
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
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
    private int serverIP;
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
    private String imageName;
    private SecretKey sharedKey;
    private IvParameterSpec sharedIv;

    private Certificate certificate;
    private Certificate rootCertificate;
    private Certificate serverCert;
    private PrivateKey privateKey;
    private PublicKey otherUserKey;
    protected boolean online;


    public Client(String serverName, int serverPort, String userName, String password) {
        this.serverName = serverName;
        this.serverPort = serverPort;
        this.userName = userName;
        this.password = password;
        this.online = true;

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

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        Boolean isLocal = true;
        Client client;
        if(args.length==2){
            client = new Client("localhost", 8818, args[0], args[1]);
        }else{
            client = new Client(args[2], 8818, args[0], args[1]);
            isLocal = false;
        }
        if (client.connect(isLocal)) {
            System.out.println("Connect successful.");
            try{
                if (!client.login()) throw new IOException();
            }catch (IOException e) {
                e.printStackTrace();
                System.out.println("Error logging in");
            }
        } else {
            System.out.println("Connect failed.\n#######################\n");
        }
    }

    private void importKeyPairFromKeystoreFile(String fileNameKS, String fileNameC, String alias, String storeType) throws Exception {
        FileInputStream keyStoreOs;
        FileInputStream rootCert;
        try{
            System.out.print("Certificates Files Present check: ");
            keyStoreOs = new FileInputStream(fileNameKS);
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
            System.out.println("Keystore present: " + (sslKeyStore != null) + "\n" );

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
            System.out.println("Local Certificates Retrieved\n###############################\n");

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

    public boolean connect(Boolean checkLocal){
        try{
            if(checkLocal){
                this.socket = new Socket(this.serverName, serverPort);
            }else{
                InetAddress addy = InetAddress.getByName(this.serverName);
                this.socket = new Socket(addy, serverPort);
            }
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

    private void closeOpenStreams(){
        try {
            ois.close();
        } catch (IOException e) {
        }
        try {
            dis.close();
        } catch (IOException e) {
        }
        try {
            serverIn.close();
        } catch (IOException e) {
        }
        scanner.close();
        System.out.println("Closed Open Streams");
        System.exit(0);
    }

    private boolean login() throws Exception {      
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
        System.out.println("Certification Step - Complete\n###############################\n");
        // Certificaition Step - END

        String cmd = "login|"+ userName + "|"+ password+"\n";
        serverOut.write(cmd.getBytes());
        String response = bufferIn.readLine();
        System.out.println("Response Line: " + response);
        if ("ok|login".equalsIgnoreCase(response)) {
            //Receive otherUserKey
            BufferedInputStream getKey = new BufferedInputStream(serverIn);
            while(getKey.available()<0){ }
            int keySize = getKey.available();
            byte[] key = new byte[294];
            getKey.read(key, 0, 294);
            String signature =" ";
            try {
                otherUserKey = KeyFactory.getInstance("RSA", BC_PROVIDER).generatePublic(new X509EncodedKeySpec(key));
            } catch (InvalidKeySpecException e) {
                System.out.println("Invalid key spec");
            } catch (NoSuchAlgorithmException e) {
                System.out.println("No such algorithm");
            }
            System.out.println("~~~");

            System.out.println("Received other user's public key");
            System.out.println("Public Key: "+ otherUserKey);
            System.out.println("~~~");

            try{
                if (userName.equalsIgnoreCase("Alice")){
                    dis = new DataInputStream(new FileInputStream(new File("../ChatServer/bSig.txt")));
                    //FileInputStream fis = new FileInputStream("../ChatServer/aSig.txt");
                    byte [] sigBytes= dis.readAllBytes();
                    signature = new String(sigBytes);
                }
                else{
                    dis = new DataInputStream(new FileInputStream(new File("../ChatServer/aSig.txt")));
                    //FileInputStream fis = new FileInputStream("../ChatServer/bSig.txt");
                    byte [] sigBytes= dis.readAllBytes();
                    signature = new String(sigBytes);
                }

            }catch(Exception e){
                e.printStackTrace();
            }
            System.out.println("Public Key Recieved" + otherUserKey != null);
            if (verify(otherUserKey.toString(),signature,serverCert.getPublicKey())){
               System.out.println("Signature verified");
               msgReader();
               msgWriter();
            }
            else{
                System.out.println("Alice/Bob public key was not verified to be from the server");
                System.out.print("Exiting program...");
                closeOpenStreams();
            }
            System.out.println("Login Complete\n###############################\n");
            return true;
        }
        System.out.println("Login Incomplete\n###############################\n");
        return false;
    }

    public void generateKey() throws NoSuchAlgorithmException { // 256 bit key for 14 rounds
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        sharedKey = keyGenerator.generateKey();
    }

    public void generateIv() { // IV vector should be the same for each client to decrypt/encrypt// reciever
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        sharedIv = new IvParameterSpec(iv);
    }

    //send our certificate to server and receive a certificate from the server then verify
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
            serverCert = cert;
            System.out.println("Server Certificate Present: " + cert != null);
            System.out.println("complete\n");
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
        Thread reader = new Thread(){
            public void run(){
                while(online){
                    String response = "";
                    try {
                        response = bufferIn.readLine();
                    } catch (IOException e) {
                        System.out.println("Socket not available");
                        System.out.println("Leaving...");
                        System.exit(0);
                    }
                    try{
                        String[] tokens = response.split(Pattern.quote("|"), 3);
                        // tokens[0] == msg keyword for server
                        // tokens[2] == message body
                        
                        if (userName.equalsIgnoreCase("Alice")) {
                            sender = "Bob";
                        } else {
                            sender = "Alice";
                        }
                        if (tokens[0].equalsIgnoreCase("online")) {
                            System.out.println(sender + " is online\n");
                            //System.out.println(otherUserCert.toString());
                            
                        } else if (tokens[0].equalsIgnoreCase("offline")) {
                            System.out.println(sender + " logged off\n");
                        } else if (tokens[0].equalsIgnoreCase("msg")) {

                            try{
                                String[] div = tokens[2].split(Pattern.quote("|"), 3); // splitting the third token
                                String ciAES = div[0];
                                String ciRSA = div[1];

                                byte[] b = new byte[16];
                                dis = new DataInputStream(new FileInputStream(new File("../ChatClient/IV.txt")));
                                dis.readFully(b);
                                iv = new IvParameterSpec(b);
                                dis.close();

                                System.out.println("Encrypted Session Key: " + ciRSA);
                                System.out.println("\nEncrypted Message: " + ciAES);

                                SecretKey aesKey = decryptRSA("RSA/ECB/PKCS1Padding", ciRSA);

                                System.out.println("\nDecrypted session Key: " + aesKey);
                                String decryptedAES = decryptAES("AES/CBC/PKCS5Padding", ciAES, aesKey, iv);
                                String decompressedData = decompress(decryptedAES);
                                System.out.println(sender + ": " + decodeText(decompressedData.split(Pattern.quote("|"),2)) + "\n");
                            }catch(Exception e){
                                e.printStackTrace();
                            }
                            
                        } else if (tokens[0].equalsIgnoreCase("img")) {
                            // System.out.println(sender + ": " + tokens[2] + "\n");
                            try {
                                String[] div = tokens[2].split(Pattern.quote("|"), 3); // splitting the third token
                                String ciAES = div[0];
                                String ciRSA = div[1];
                                imageName = new String(div[2]);
                                byte[] b = new byte[16];
                                dis = new DataInputStream(new FileInputStream(new File("../ChatClient/IV.txt")));
                                dis.readFully(b);
                                iv = new IvParameterSpec(b);
                                dis.close();

                                System.out.println("\nEncrypted Message: " + ciAES);
                                System.out.println("\nEncrypted Session Key: " + ciRSA);
                                
                                SecretKey aesKey = decryptRSA("RSA/ECB/PKCS1Padding", ciRSA);
                                System.out.println("\nDecrypted Session Key: " + aesKey);
                                String decryptedAES = decryptAES("AES/CBC/PKCS5Padding", ciAES, aesKey, iv);
                                String decompressedData = decompress(decryptedAES);
                                String[] imgCap = decompressedData.split(Pattern.quote("|"), 2);
                                decodeString(imgCap);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        } else {
                            System.out.println(response + "\n");
                        }
                    }catch (Exception e) {
                        e.printStackTrace();
                        break;
                    }
                    System.out.println("---");
                }
            }
        };
        reader.start();
    }

    private void msgWriter() {
        if (userName.equalsIgnoreCase("Alice")) {
            receiver = "Bob";
        } else {
            receiver = "Alice";
        }
        Thread writer = new Thread() {
            public void run() {
                while (online) {
                    String message = scanner.nextLine();
                    String [] tokens = message.split(Pattern.quote("|"), 3);
                    if(message.equalsIgnoreCase("quit") || message.equalsIgnoreCase("logoff")){
                        String cmd = "quit";
                        online = false;
                        try{
                            serverOut.write(cmd.getBytes());
                        }catch (IOException e) {
                            e.printStackTrace();
                        }
                        closeOpenStreams();
                    } else if (tokens[0].equalsIgnoreCase("img")) {
                        try {
                            generateKey();
                            generateIv();
                            FileOutputStream fos = new FileOutputStream(new File("IV.txt"));
                            BufferedOutputStream bos = new BufferedOutputStream(fos);
                            bos.write(sharedIv.getIV());
                            bos.close();
                            imageName = tokens[2];
                            System.out.println("Session Key: " + sharedKey);
                            cipherAES = encryptAES("AES/CBC/PKCS5Padding", encodeString(tokens, receiver), sharedKey,
                                    sharedIv);
                            cipherRSA = encryptRSA("RSA/ECB/PKCS1Padding", sharedKey, otherUserKey);

                            System.out.println("\nEncrypted Session Key: " + cipherRSA);
                            System.out.println("\nEncrypted Message: " + cipherAES);

                            String cmd = "img" + "|" + receiver + "|" + cipherAES + "|" + cipherRSA +"|"+ imageName + "\n";
                            //System.out.println("writing to server");
                            serverOut.write(cmd.getBytes());
                            //System.out.println("wrote to server");
                        }catch (Exception e) {
                            e.printStackTrace();
                        }
                    } else {
                        try {
                            generateKey();
                            generateIv();
                            FileOutputStream fos = new FileOutputStream(new File("IV.txt"));
                            BufferedOutputStream bos = new BufferedOutputStream(fos);
                            bos.write(sharedIv.getIV());
                            bos.close();
                            System.out.println("Session Key: " + sharedKey);
                            cipherAES = encryptAES("AES/CBC/PKCS5Padding", encodeText(message, receiver), sharedKey,
                                    sharedIv);
                            cipherRSA = encryptRSA("RSA/ECB/PKCS1Padding", sharedKey, otherUserKey);

                            System.out.println("\nEncrypted Session Key: " + cipherRSA);
                            System.out.println("\nEncrypted Message: " + cipherAES);

                            String cmd = "msg|" + receiver + "|" + cipherAES + "|" + cipherRSA + "\n";
                            serverOut.write(cmd.getBytes());
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                    System.out.println("---");
                }
                
            }
        };
        writer.start();
    }

    private String encodeString(String[] tokens, String receiver) throws Exception { // tokens format:
        // [img,caption,file]
        String caption = tokens[1];

        File f = new File("../SendingImages/"+tokens[2]); // file to be taken in (image path)
        FileInputStream fis = new FileInputStream(f); // taking in file
        System.out.println("Still sending to server....");
        byte imageData[] = new byte[(int) f.length()];
        fis.read(imageData);
        String base64Image = Base64.getEncoder().encodeToString(imageData);

        String hashout = sha256(base64Image + "|" + caption);
        String signature = sign(hashout,privateKey);
        String encodedImgCap = compress(base64Image + "|" + caption + "|" + hashout+ "|"+ signature);

        System.out.println("Hashed Image Details: " + hashout);
        return encodedImgCap;
    }

    // token format from server: [baseImage,caption]
    private void decodeString(String[] tokens) throws Exception { // tokens format: ["img",reciever,caption base64Image]
                                                                  // -- takes in the caption + baseimage as one
        System.out.println("Recieving from server...");
        FileOutputStream fos = new FileOutputStream("../RecievedImages/"+imageName); // where the new
                                                                                                   // file
                                                                                                   // will be saved
        try {
            String[] captionHashSign = new String(tokens[1]).split(Pattern.quote("|"), 3);
            
            //calculating hash
            String hashin = sha256(tokens[0]+"|"+captionHashSign[0]);
            String signature = captionHashSign[2];
            System.out.println("\nHashed Image Details: " + hashin);
            
            if (captionHashSign[1].equalsIgnoreCase(hashin) && verify(hashin, signature,otherUserKey)) {
                String file = new String(tokens[0]).replaceAll(" +", "+");
                byte[] b = Base64.getDecoder().decode(file);
                fos.write(b); // write bytes to new file
                //System.out.println("Received!");
                System.out.println("\nImage received from: "+ sender);
                System.out.println("Image filename: " + imageName);
                System.out.println("Image caption: " +  captionHashSign[0]);
            } else {
                System.out.println("Confidentiality breached! Could not receive file because it has been compromised.");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private String encodeText(String message, String reciever) throws IOException {
        String base64Msg = Base64.getEncoder().encodeToString(message.getBytes());
        String hashout = sha256(base64Msg);
        System.out.println("Hashed Message: " + hashout);
        String encodedMsg = compress(base64Msg + "|" + hashout);
        return encodedMsg;
    }

    private String decodeText(String[] tokens) throws Exception { // tokens format: ["img",reciever,caption base64Image]
                                                                  // -- takes in the caption + baseimage as one
        String text = "";
        try {
            String textHash = tokens[1];

            // calculating hash
            String hashin = sha256(tokens[0]);
            System.out.println("\nHashed Message: " + hashin);
            if (textHash.equalsIgnoreCase(hashin)) {
                byte[] b = Base64.getDecoder().decode(tokens[0]);
                text = new String (b);
            } else {
                System.out.println("Confidentiality breached!");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return text;
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
    private String encryptRSA(String algorithm, SecretKey input, PublicKey pkey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance(algorithm, new BouncyCastleProvider());
        cipher.init(Cipher.ENCRYPT_MODE, pkey);
        byte[] cipherText = cipher.doFinal(input.getEncoded());
 
        return Base64.getEncoder().encodeToString(cipherText);
    }

    private SecretKey decryptRSA(String algorithm, String input) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm, new BouncyCastleProvider());
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedBytes = Base64.getDecoder().decode(input);

        byte[] cipherText = cipher.doFinal(decodedBytes);
        SecretKey originalKey = new SecretKeySpec(cipherText, 0, cipherText.length, "AES");
        return originalKey;
    }

    // hashing
    private static String sha256(String rawinput) {
        String hashout = "";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.reset();
            digest.update(rawinput.getBytes("utf8"));
            hashout = String.format("%040x", new BigInteger(1, digest.digest()));
        } catch (Exception E) {
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
    //Method for signing (Integrity)
    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(plainText.getBytes(StandardCharsets.UTF_8));
    
        byte[] signature = privateSignature.sign();
    
        return Base64.getEncoder().encodeToString(signature);
    }


    //Verify method for signing
    public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(plainText.getBytes(StandardCharsets.UTF_8));
    
        byte[] signatureBytes = Base64.getDecoder().decode(signature);
    
        return publicSignature.verify(signatureBytes);
    }



}

// Assume that server is already authenticated and known to client
// From the sever we need to get the other client's certificate to verify
// customer as trustworthy
// Thus certify othe client's certificate not server's certificate
// Keep the CA server certificate as a trusted certificate.