package ChatClient;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Scanner;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Client{
    private final String serverName;
    private final int serverPort;
    private OutputStream serverOut;
    private InputStream serverIn;
    private BufferedReader bufferIn;
    private final String userName;
    private final String password;
    private static final String BC_PROVIDER = "BC";
    private Socket socket;
    private Scanner scanner;
    private Certificate certificate;
    private Certificate rootCertificate;
    private PrivateKey privatetKey;


    public Client(String serverName, int serverPort, String userName, String password){
        this.serverName = serverName;
        this.serverPort = serverPort;
        this.userName = userName;
        this.password = password;
    }

    public static void main(String[] args){
        Client client = new Client("localhost", 8818, args[0], args[1]);
        if(client.connect()){
            System.out.println("Connect successful.");
            try {
                client.login();            
            } catch (IOException e) {
                System.out.println("Error logging in");
            }
        }
        else{
            System.out.println("Connect failed.");
        }
    }

    public boolean connect(){
        try{
            this.socket = new Socket(serverName, serverPort);
            System.out.println("Connected to server");
            this.serverOut = socket.getOutputStream();
            this.serverIn = socket.getInputStream();
            this.bufferIn = new BufferedReader(new InputStreamReader(serverIn));
            this.scanner = new Scanner(System.in);
            return true;

        } catch(Exception e){
            System.out.println("Unable to connect");
            e.printStackTrace();
        }
        return false;
    }

    private boolean login() throws IOException {
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
        System.out.println("Response Line: "+ response);
        if("ok login".equalsIgnoreCase(response)){
            msgReader();
            msgWriter();
            return true;
        }
        else{
            return false;
        }
    }

    private void handleCertification() throws IOException, InterruptedException{
        System.out.println("Sending certificate to Server");
        InputStream input = this.serverIn;
        OutputStream output = this.serverOut;

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

        //////////////////////////////////////////
        CertificateFactory certFactory = null;                        
        Certificate cert = null; // server certificate

        /**
         * Verifying server the X509 certificate 
        **/
        try{
            certFactory = CertificateFactory.getInstance("X.509");                        
            cert = certFactory.generateCertificate(input);
            System.out.println("X.509 Certificate Constructed");
        }catch( CertificateException e ){
            System.out.println("X.509 Certificate Not Constructed");
            e.printStackTrace();
        } 

        /**
         * Verifying server the X509 certificate 
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

    }


    private void msgReader(){
        Thread t = new Thread(){
            public void run(){
                while(true){
                    try {
                        String response = bufferIn.readLine();
                        String [] tokens = response.split(" ", 3);
                        String sender;
                        //tokens[0] == msg keyword for server, tokens[2] == message body
                        if(userName.equalsIgnoreCase("Alice")){
                            sender = "Bob";
                        }
                        else{
                            sender = "Alice";
                        }
                        if(tokens[0].equalsIgnoreCase("online")){
                            //System.out.println("inside condition 1");
                            System.out.println(sender +" is online\n");
                        }
                        else if(tokens[0].equalsIgnoreCase("Offline")){
                            System.out.println(sender +" logged off\n");
                        }
                        else if(tokens[0].equalsIgnoreCase("msg")){
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
        String receiver;
            if(userName.equalsIgnoreCase("Alice")){
                receiver = "Bob";
            }
            else{
                receiver = "Alice";
            }
        Thread t = new Thread(){
            public void run(){
                boolean online = true;
                while(online == true){
                    String message = scanner.nextLine();
                    if(message.equalsIgnoreCase("quit") || message.equalsIgnoreCase("logoff")){
                        String cmd = "quit";
                        try {
                            serverOut.write(cmd.getBytes());
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        break;
                    }
                    else{
                        String cmd = "msg "+ receiver + " "+ message+"\n";
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

}

/*public class Client {
    private final String serverName;
    private final int serverPort;
    private OutputStream serverOut;
    private Socket socket;
    private InputStream serverIn;
    private BufferedReader bufferIn;

    private ArrayList<UserStatusListener> listeners = new ArrayList<>();
    private ArrayList<MessageListener> messages = new ArrayList<>();

    public Client(String serverName, int serverPort){
        this.serverName = serverName;
        this.serverPort = serverPort;
    }

    public static void main(String [] args) throws IOException {
        Client client = new Client("localhost", 8818);

        client.addListener(new UserStatusListener(){
            @Override
            public void online(String login) {
                System.out.println("Online: "+login);
                
            }
            @Override
            public void offline(String login) {
                System.out.println("Offline: "+login);    
            }
            
        });

        client.addMessageListeners(new MessageListener(){

            @Override
            public void onMessage(String fromLogin, String msgBody) {
                System.out.println("You have a message from "+ fromLogin);
                System.out.println("Message: "+ msgBody);
                
            }
            
        });

        if(!client.connect()){
            System.err.println("Connect failed.");
        }
        else{
            System.out.println("Connect successful.");

            if(client.login("guest", "guest")){
                System.out.println("Login Successful");
                client.msg("jim", "Hello World");
            }
            else{
                System.out.println("Login Failed");
            }

            //client.logOff();
            
        }
    }

    private void msg(String sendto, String msgbody) throws IOException {
        String cmd = "msg " + sendto + " "+ msgbody +"\n";
        serverOut.write(cmd.getBytes());
    }

    private void logOff() throws IOException {
        String cmd = "logoff\n";
        serverOut.write(cmd.getBytes());

    }

    private boolean login(String userName, String password) throws IOException {
        String cmd = "login "+ userName + " "+ password+"\n";
        serverOut.write(cmd.getBytes());
        String response = bufferIn.readLine();
        System.out.println("Response Line: "+ response);
        if("ok login".equalsIgnoreCase(response)){
            startMessageReader();
            return true;
        }
        else{
            return false;
        }
    }

    private void startMessageReader() {
        Thread t = new Thread(){
            public void run(){
                readMessageLoop();
            }
        };
        t.start();
    }

    protected void readMessageLoop() {
        try{
            String line;
            while((line = bufferIn.readLine())!=null){
                String [] tokens = line.split(" ", 3);
                if(tokens!=null & tokens.length>0){
                    String cmd = tokens[0];
                    if ("online".equalsIgnoreCase(cmd)){
                        handleOnline(tokens);
                    }
                    else if ("offline".equalsIgnoreCase(cmd)){
                        handleOffline(tokens);
                    }
                    else if ("msg".equalsIgnoreCase(cmd)){
                        handleMessage(tokens);
                    }

                }
                
            }
        } catch (Exception e){
            e.printStackTrace();
            try {
                socket.close();
            } catch (IOException e1) {
                e1.printStackTrace();
            }
        }
    }

    private void handleMessage(String [] tokens) {
        String login = tokens [1];
        String msgBody = tokens[2];

        for(MessageListener message : messages){
            message.onMessage(login, msgBody);
        }
    }

    private void handleOffline(String[] tokens) {
        String login = tokens [1];
        for(UserStatusListener listener: listeners){
            listener.offline(login);
        }
    }

    private void handleOnline(String [] tokens) {
        String login = tokens [1];
        for(UserStatusListener listener: listeners){
            listener.online(login);
        }
    }

    private boolean connect() {
        try {
            this.socket = new Socket(serverName, serverPort);
            System.out.println("Client port is "+socket.getLocalPort());
            this.serverOut = socket.getOutputStream();
            this.serverIn = socket.getInputStream();
            this.bufferIn = new BufferedReader(new InputStreamReader(serverIn));
            return true; 
        } catch (IOException e) {
            e.printStackTrace();
        }
        return false;
    }

    public void addListener(UserStatusListener userListener){
        listeners.add(userListener);
    }
    public void removeListener(UserStatusListener userListener){
        listeners.remove(userListener);
    }

    public void addMessageListeners(MessageListener message){
        messages.add(message);
    }

    public void removeMessageListeners(MessageListener message){
        messages.remove(message);
    }
}*/
