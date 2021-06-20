package ChatServer;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;
import java.security.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ServerWorker extends Thread {
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
            
            cert = (X509Certificate) certFactory.generateCertificate(bis);
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

    /*private void handleMessage(String [] tokens) {
        String sendTo = tokens [1];
        String msg = tokens[2];

        List <ServerWorker> workerList = server.getWorkerList();
        for(ServerWorker worker: workerList){
            //if sendTo.equalsIgnoreCase()
        }
    }*/
}
