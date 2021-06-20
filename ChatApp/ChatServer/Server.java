package ChatServer;

import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.*;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.ByteArrayInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Server {
    private final int serverPort;
    private ArrayList<ServerWorker> workerList = new ArrayList<>();
    private ArrayList<UserClient> userList = new ArrayList<>();
    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private Certificate certificate;
    private Certificate rootCertificate;
    private PrivateKey privateKey;
    

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
    
    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        int port = 8818;
        Server server = new Server(port);
        server.run();
    }

    public Server (int serverPort){
        this.serverPort = serverPort;
        try{
            importKeyPairFromKeystoreFile("PGP-icert.pfx", "PGP-icert.cer", "PKCS12");
        } catch(Exception e){
            e.printStackTrace();
        }   
    }

    public List<ServerWorker> getWorkerList(){
        return workerList;
    }

    public void run(){
        try (ServerSocket serverSocket = new ServerSocket(serverPort)){
            while(true){
                System.out.println("Server is alive");
                Socket clientSocket = serverSocket.accept();
                ServerWorker worker = new ServerWorker(this, clientSocket);
                //ServerWorker worker = new ServerWorker(this, clientSocket);
                workerList.add(worker);
                worker.start();
                System.out.println("New ServerWorker Thread created");
                
            }
        } catch (IOException e) {
            System.out.println("Server issues");
            e.printStackTrace();
        }
    }

    public void removeWorker(ServerWorker serverWorker) {
        workerList.remove(serverWorker);
    }

    private class ServerWorker extends Thread {
        private final Socket clientSocket;
        private final Server server;
        private String login = null;
        private OutputStream output;
    
        public ServerWorker(Server server, Socket clientSocket){
            this.server = server;
            this.clientSocket = clientSocket;
        }
    
        public void run() {
            try{
                HandleClient();
            } catch (IOException e){
                e.printStackTrace();
            } catch (InterruptedException e){
                e.printStackTrace();
            }
        }

        private Certificate handleCertification() throws IOException, InterruptedException{
            System.out.println("Accepting certificate from Client");

            InputStream input = clientSocket.getInputStream();
            this.output = clientSocket.getOutputStream();
            //userCert = new FileInputStream(fileNameC);

            CertificateFactory certFactory = null;                        
            Certificate cert = null; // client certificate
            
            // to construct Certificate from client bytestream
            try{
                BufferedInputStream bis = new BufferedInputStream(input);
                System.out.print("Check User (A/B) Certificate: ");
                System.out.println(cert);
                certFactory = CertificateFactory.getInstance("X.509");
                
                cert = (X509Certificate)certFactory.generateCertificate(bis);
                System.out.println(cert);
                System.out.println("X.509 Certificate Constructed");
            }catch( CertificateException e ){
                System.out.println("X.509 Certificate Not Constructed");
                e.printStackTrace();
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
    
        private void HandleClient() throws IOException, InterruptedException{
            System.out.println("Server is still alive");
    
            InputStream input = clientSocket.getInputStream();
            this.output = clientSocket.getOutputStream();
            // Certificaition Step
            Certificate cert = handleCertification();
            // Certificaition Step
    
            BufferedReader reader = new BufferedReader(new InputStreamReader(input));
            
            String line; 
    
            while((line=reader.readLine())!=null){
                String [] tokens = line.split(" ");
                String cmd = tokens[0];
                if (tokens !=null && tokens.length>0){
                    if("quit".equalsIgnoreCase(cmd) || "logoff".equalsIgnoreCase(cmd)){
                        handleLogoff();
                        break;
                    }else if("login".equalsIgnoreCase(cmd)){
                        handleLogin(output, tokens, cert);
                    }
                    else if ("msg".equalsIgnoreCase(cmd)){
                        String[] msgTokens = line.split(" ", 3);
                        handleMessage(msgTokens);
                    }
                    else{
                        String msg = "Unknown " + cmd + "\n";
                        output.write(msg.getBytes());   
                    } 
                }
                         
            }
        }
    
        //format msg login msg
        private void handleMessage(String[] tokens) throws IOException {
            String sendTo = tokens[1];
            String body = tokens[2];
    
            List<ServerWorker> workerList = server.getWorkerList();
            for(ServerWorker worker: workerList){
                if(sendTo.equalsIgnoreCase(worker.getLogin())){
                    String outMsg = "msg "+ login +" "+ body+ "\n";
                    worker.send(outMsg);
                }
            }
        }
    
        private void handleLogoff() throws IOException {
            server.removeWorker(this);
            System.out.println("User logged off successfully: "+ login);
            String offLineMsg = "Offline "+login +"\n";
            List<ServerWorker> workerList = server.getWorkerList();
            for(ServerWorker worker: workerList){
                if(!login.equals(worker.getLogin())){
                    worker.send(offLineMsg);
                }
            }
            clientSocket.close();
        }
    
        public String getLogin(){
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
                        
                    }
                    //send other online users current user's status
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
            if(login !=null){
                output.write(msg.getBytes());
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
            this.userName = userName;
            this.SHAedPW = generateSHA(userName, password);
        }
    
        private byte[] generateSHA(String user, String pw){
            Security.addProvider(new BouncyCastleProvider());
            byte[] hPassword = new byte[0];
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
        
        //public static void main(String args[]){
        //    String u = args[0];
        //    String p = args[1];
        //    UserClient uc = new UserClient(u, p, null);
        //    try{
        //        System.out.println(uc.checkSHA());
        //    } catch(Exception e ){}
        //}           
    }

}
