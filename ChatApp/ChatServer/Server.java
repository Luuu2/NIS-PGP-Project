package ChatServer;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.*;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.ByteArrayInputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.File;
import java.nio.file.Files;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Server {
    private final int serverPort;
    private ArrayList<ServerWorker> workerList = new ArrayList<>();
    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private Certificate certificate;
    private Certificate rootCertificate;
    private PrivateKey privatetKey;
    

    private void importKeyPairFromKeystoreFile(String fileNameKS, String fileNameC, String storeType) throws Exception {
        FileInputStream keyStoreOs;
        FileInputStream certOs;
        try{
            keyStoreOs = new FileInputStream(fileNameKS);
            certOs = new FileInputStream(fileNameC);

            System.out.println(keyStoreOs);
            System.out.println(certOs);
            KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);

            char[] keyPassword = "pass".toCharArray();
            sslKeyStore.load(keyStoreOs, keyPassword);
            String alias = "PGP-icert";

            KeyStore.ProtectionParameter entryPassword = new KeyStore.PasswordProtection(keyPassword);

            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry)
            sslKeyStore.getEntry(alias, entryPassword);

            this.privatetKey = privateKeyEntry.getPrivateKey();
            System.out.println("Private Key");
            System.out.println(this.privatetKey );

            // GET CERT
            this.certificate = privateKeyEntry.getCertificate();
            System.out.println("Certificate");
            System.out.println(this.certificate);
            //

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
                ServerWorker worker = new ServerWorker( this, clientSocket);
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
        int i = 0;
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

        private void handleCertification() throws IOException, InterruptedException{
            System.out.println("Accepting certificate from Client");

            InputStream input = clientSocket.getInputStream();
            this.output = clientSocket.getOutputStream();

            CertificateFactory certFactory = null;                        
            Certificate cert = null; // client certificate
            
            // to construct Certificate from client bytestream
            try{
                certFactory = CertificateFactory.getInstance("X.509");                        
                cert = certFactory.generateCertificate(input);
                System.out.println("X.509 Certificate Constructed");
            }catch( CertificateException e ){
                System.out.println("X.509 Certificate Not Constructed");
                e.printStackTrace();
            } 

            /**
             * Verifying user the X509 certificate 
            **/
            try {
                cert.verify(rootCertificate.getPublicKey(), Security.getProvider(BC_PROVIDER)); 
            } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException e) {
                //handle wrong algos
                System.out.print("handle wrong algorithms");
            } catch (SignatureException ex) {
                //signature validation error
                System.out.print("signature validation error");
            }
            //////////////////////////////////////
            //////////////////////////////////////
            /**
             * Sending user the server X509 certificate 
            **/
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

        }
    
        private void HandleClient() throws IOException, InterruptedException{
            System.out.println("Server is still alive");
    
            InputStream input = clientSocket.getInputStream();
            this.output = clientSocket.getOutputStream();
            // Certificaition Step
            handleCertification();
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
                        handleLogin(output, tokens);
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
    
        private void handleLogin(OutputStream output, String[] tokens) throws IOException {
            if(tokens.length == 3){
                String login = tokens[1];
                String password = tokens[2];

                /// Verify User via Cert 
                ///output.write(msg.getBytes());
                ///
    
                if (login.equals("Alice") && password.equals("Alice") || login.equals("Bob") && password.equals("Bob")){
                    String msg = "ok login\n";
                    output.write(msg.getBytes());
                    this.login = login;
                    System.out.println("User logged in successfully:" + login);
                    
                    String onlineMsg = "online "+login +"\n";
                    List<ServerWorker> workerList = server.getWorkerList();
    
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
    
        /*private void handleMessage(String [] tokens) {
            String sendTo = tokens [1];
            String msg = tokens[2];
    
            List <ServerWorker> workerList = server.getWorkerList();
            for(ServerWorker worker: workerList){
                //if sendTo.equalsIgnoreCase()
            }
        }*/
    }
    
}
