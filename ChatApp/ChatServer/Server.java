package ChatServer;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Scanner;

import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import java.net.ServerSocket;
import java.net.Socket;

import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import javax.security.auth.x500.X500Principal;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;



public class Server {
    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    
    private final int serverPort;

    private ArrayList<UserClient> userList = new ArrayList<>();
    private ArrayList<ServerWorker> workerList = new ArrayList<>();
    private SecretKey sharedKey;
    private IvParameterSpec sharedIv;
    
    private Certificate certificate;
    private Certificate rootCertificate;
    private PrivateKey privateKey;
 
    public Server(int serverPort) {
        this.serverPort = serverPort;
        
        try{
            importKeyPairFromKeystoreFile("PGP-icert.pfx", "PGP-icert.cer", "PKCS12");
        } catch(Exception e){
            e.printStackTrace();
        }   
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        int port = 8818;
        Server server = new Server(port);
        try{
            server.run();
        } catch (Exception e){
            System.out.println("Run Broke");
            e.printStackTrace();
        }
        
    }


    private void importKeyPairFromKeystoreFile(String fileNameKS, String fileNameC, String storeType) throws Exception {
        FileInputStream keyStoreOs;
        FileInputStream certOs;
        FileInputStream rootCert;
        try{
            keyStoreOs = new FileInputStream(fileNameKS);
            certOs = new FileInputStream(fileNameC);
            rootCert = new FileInputStream("PGP-rcert.cer");

            System.out.println(keyStoreOs);
            System.out.println(certOs);
            KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);

            char[] keyPassword = "pass".toCharArray();
            sslKeyStore.load(keyStoreOs, keyPassword);
            String alias = "PGP-icert";

            KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyPassword);

            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)
            sslKeyStore.getEntry(alias, entryPassword);

            this.privateKey = privateKeyEntry.getPrivateKey();
            System.out.println("Private Key");
            System.out.println(this.privateKey);

            // GET CERT
            this.certificate = privateKeyEntry.getCertificate();
            System.out.println("Certificate");
            System.out.println(this.certificate);
            //

            CertificateFactory cf = CertificateFactory.getInstance("X.509", BC_PROVIDER);
            System.out.println("Root Certification Check");
            BufferedInputStream bisCertR = new BufferedInputStream(rootCert);
            while (bisCertR.available() > 0) {
                System.out.println("Root Cert");
                //System.out.println(bisCertR);
                this.rootCertificate = cf.generateCertificate(bisCertR);
                System.out.println(rootCertificate);
            }
        } catch(Exception e){
            System.out.println(e);
            System.exit(0);
        }
    }


    public List<ServerWorker> getWorkerList() {
        return workerList;
    }

    public void run() throws NoSuchAlgorithmException {
        generateKey();
        generateIv();
        ObjectOutputStream oos;
        FileOutputStream fos;
        try {
            oos = new ObjectOutputStream(new FileOutputStream("Key.txt"));
            oos.writeObject(sharedKey);
            oos.close();
            fos = new FileOutputStream(new File("IV.txt"));
            BufferedOutputStream bos = new BufferedOutputStream(fos);
            bos.write(sharedIv.getIV());
            bos.close();
        } catch (FileNotFoundException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        } catch (IOException e1) {
            // TODO Auto-generated catch block
            e1.printStackTrace();
        }
        
        try (ServerSocket serverSocket = new ServerSocket(serverPort)) {
            while (true) {
                System.out.println("Server is alive");
                Socket clientSocket = serverSocket.accept();
                ServerWorker worker = new ServerWorker(this, clientSocket, sharedKey, sharedIv);
                workerList.add(worker);
                worker.start();
                System.out.println("New ServerWorker Thread created");

            }
        } catch (IOException e) {
            System.out.println("Server issues");
            e.printStackTrace();
        }
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

    public void removeWorker(ServerWorker serverWorker) {
        workerList.remove(serverWorker);
    }
    public class ServerWorker extends Thread  {
        private final Socket clientSocket;
        private String login = null;
        private final Server server;
        private OutputStream output;
        private InputStream input;
        private SecretKey sharedKey;
        ObjectOutputStream objectOutputStream;
        private IvParameterSpec sharedIv;
        private DataOutputStream dos;
        public ServerWorker(Server server, Socket clientSocket, SecretKey key, IvParameterSpec iv) {
            this.server = server;
            this.clientSocket = clientSocket;
            this.sharedKey = key;
            this.sharedIv = iv;
        }
        
        public void run() {
            try {
                HandleClient(); // this method is only ever called when a thread is started
                System.out.println("Running HandleClient...");
            } catch (IOException e) {
                e.printStackTrace();
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }

        private Certificate handleCertification() throws IOException, InterruptedException{
            System.out.println("Accepting certificate from Client");

            InputStream input = clientSocket.getInputStream();
            //userCert = new FileInputStream(fileNameC);
            this.output = clientSocket.getOutputStream();

            CertificateFactory certFactory = null;                        
            Certificate cert = null; // client certificate
            // to construct Certificate from client bytestream
            
            try{
                BufferedInputStream bis = new BufferedInputStream(input);
                System.out.print("Check User (A/B) Certificate: ");
                System.out.println(cert);
                certFactory = CertificateFactory.getInstance("X.509");
                
                System.out.println(cert);
                cert = (X509Certificate)certFactory.generateCertificate(bis);
                System.out.println("X.509 Certificate Constructed");
            }catch( CertificateException e ){
                e.printStackTrace();
                System.out.println("X.509 Certificate Not Constructed");
            }
            /**
             * Verifying user the X509 certificate 
            **/
            try {
                System.out.println("Verification of User Certificate");
                cert.verify(rootCertificate.getPublicKey(), Security.getProvider(BC_PROVIDER)); 
            } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException e) {
                //handle wrong algos
                System.out.print("Handle wrong algorithms");
            } catch (SignatureException ex) {
                //signature validation error
                System.out.print("Signature validation error");
                clientSocket.close();
                return null;
            }
            ////////////////////handleLogin//////////////////
            //////////////////////////////////////
            // 
            //  Sending user the server X509 certificate 
            // /
            System.out.println("Sending certificate to Client");
            // Convert CERT into byte[]
            byte[] certificateBytes = null;
            try{
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

            return cert;

        }
        private void HandleClient() throws IOException, InterruptedException {
            System.out.println("Server is still alive");
    
            this.input = clientSocket.getInputStream();
            this.objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
            this.output = clientSocket.getOutputStream();
            this.dos = new DataOutputStream(output);
            // Certificaition Step
            Certificate cert = handleCertification();
            // Certificaition Step
            BufferedReader reader = new BufferedReader(new InputStreamReader(input));
            String line;
            while ((line = reader.readLine()) != null) {
    
                String[] tokens = line.split(" ",3);
                String cmd = tokens[0];
                System.out.println("In handle client...");
                System.out.println(cmd);
                if (tokens != null && tokens.length > 0) {
                    System.out.println("Looking at tokens...");
                    if ("quit".equalsIgnoreCase(cmd) || "logoff".equalsIgnoreCase(cmd)) {
                        handleLogoff();
                        break;
                        
                    } else if ("login".equalsIgnoreCase(cmd)) {
                        System.out.println(sharedKey);
                        System.out.println(sharedIv);
                        handleLogin(output, tokens, cert);
                    } else if ("msg".equalsIgnoreCase(cmd)) {
                        String[] msgTokens = line.split(" ", 3);
                        handleMessage(msgTokens);
                    } else if ("img".equalsIgnoreCase(cmd)) {
                        //String[] imgTokens = line.split(" ", 3);
                        handleImage(tokens);
                    } else {
                        String msg = "Unknown " + cmd + "\n";
                        output.write(msg.getBytes());
                    }
                }
            }
        }
    
        public void generateKey(String name) throws NoSuchAlgorithmException { // 256 bit key for 14 rounds
    
            String sendTo = name; // reciever
            List<ServerWorker> workerList = server.getWorkerList();
            for (ServerWorker worker : workerList) {
                if (sendTo.equalsIgnoreCase(worker.getLogin())) {
                    try {
                        worker.sendKey(sharedKey);
                        System.out.println(sharedKey);
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }
            }
    
        }
        private void sendKey(SecretKey key) throws IOException {
            if (login != null) {
                dos.write(key.getEncoded());
               // objectOutputStream.writeObject(key);
            }
        }
                
        public void generateIv(String name) { // IV vector should be the same for each client to decrypt/encrypt
            String sendTo = name; // reciever
            List<ServerWorker> workerList = server.getWorkerList();
            for (ServerWorker worker : workerList) {
                if (sendTo.equalsIgnoreCase(worker.getLogin())) {
                    try {
                        //IvParameterSpec Iv = new IvParameterSpec(iv);
                        output.write(sharedIv.getIV());
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    
        private void handleImage(String[] tokens) {
            String sendTo = tokens[1];
            String cipher = tokens[2];
            System.out.println("handling image");
            System.out.println(sendTo);
            System.out.println(cipher);
            List<ServerWorker> workerList = server.getWorkerList();
            for (ServerWorker worker : workerList) {
                if (sendTo.equalsIgnoreCase(worker.getLogin())) {
                    String outMsg = "img " + login + " " + cipher + "\n";
                    try {
                        worker.send(outMsg);
                    } catch (IOException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }
                }
            }
        }
    
        // format msg login msg
        private void handleMessage(String[] tokens) throws IOException {
            String sendTo = tokens[1];
            String body = tokens[2];
    
            List<ServerWorker> workerList = server.getWorkerList();
            for (ServerWorker worker : workerList) {
                if (sendTo.equalsIgnoreCase(worker.getLogin())) {
                    String outMsg = "msg " + login + " " + body + "\n";
                    worker.send(outMsg);
                }
            }
        }
    
        private void handleLogoff() throws IOException {
            server.removeWorker(this);
            System.out.println("User logged off successfully: " + login);
            String offLineMsg = "Offline " + login + "\n";
            List<ServerWorker> workerList = server.getWorkerList();
            for (ServerWorker worker : workerList) {
                if (!login.equals(worker.getLogin())) {
                    worker.send(offLineMsg);
                }
            }
            clientSocket.close();
        }
    
        public String getLogin() {
            return login;
        }
    
        private void handleLogin(OutputStream output, String[] tokens, Certificate certificate) throws IOException {
            if(tokens.length == 3){
                String login = tokens[1];
                String password = tokens[2];
                
                UserClient user = new UserClient(login, password, certificate);
                if (user.checkSHA()&& certificate!=null){
                    String msg = "ok login\n";
                    output.write(msg.getBytes());
                    this.login = login;
                    System.out.println("User logged in successfully:" + login);
                    String onlineMsg = "online "+login +"\n";
                    List<ServerWorker> workerList = server.getWorkerList();
                    server.userList.add(user);
    
                    //send current user all other online logins
                    for(ServerWorker worker: workerList){
                        if(worker.getLogin() != null){
                            if(!login.equals(worker.getLogin())){
                                String msg2 = "online "+ worker.getLogin() + '\n';
                                send(msg2);
                            }
                        }
                    //send other online users current user's status
                    }
                    
                    for(ServerWorker worker: workerList){
                        if(!login.equals(worker.getLogin())){
                            worker.send(onlineMsg);
                        }
                    }
                }
                else {
                    String msg = "error login\n";
                    System.out.println("Unsuccessful login attempt");
                    output.write(msg.getBytes());
                }
            }
        }
    
        private void send(String msg) throws IOException {
                output.write(msg.getBytes());
            if(login !=null){
            }
        }
        private void send(byte[] bytes) throws IOException {

            output.write(bytes);
        }
    }


    public class UserClient{
        private static final String BC_PROVIDER = "BC";
        private final Certificate certificate;
        private final String userName;
        private final byte[] SHAedPW;
    
        public UserClient(String userName, String password, Certificate certificate){
            this.certificate = certificate;
            this.SHAedPW = generateSHA(userName, password);
            this.userName = userName;
    
        }
        private byte[] generateSHA(String user, String pw){
            byte[] hPassword = new byte[0];
            Security.addProvider(new BouncyCastleProvider());
            try{
                MessageDigest md = MessageDigest.getInstance("SHA-256", BC_PROVIDER);
                md.update(md.digest( (user + " " + pw).getBytes(StandardCharsets.UTF_8) ));
                hPassword = md.digest( pw.getBytes(StandardCharsets.UTF_8) );
            }catch(Exception e){
                e.printStackTrace();
            }
            return hPassword;
        }
    
        public boolean checkSHA() throws FileNotFoundException{
            File sct = new File("ServerCoolTings.txt");
            Scanner scan = new Scanner(sct);
            while(scan.hasNextLine()){
                String line = scan.nextLine().replace("\n", "");
                if(line.startsWith(this.userName)){
                    String shaValue = line.split(":")[1];
                    String stringSHAedPW = Arrays.toString( SHAedPW ).replace(" ", "").replace("]", "").replace("[", "");
                    scan.close();
                    return shaValue.equals(stringSHAedPW);
                }
            }
            scan.close();
            return false;
        }
    }
    
}
