package ChatServer;

import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import javax.imageio.ImageIO;

import java.io.InputStreamReader;
import java.io.OutputStream;
import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
//import org.apache.commons.lang3.StringUtils;


public class ServerWorker extends Thread {
    private final Socket clientSocket;
    private final Server server;
    private String login = null;
    private OutputStream output;
    private InputStream input;

    public ServerWorker(Server server, Socket clientSocket){
        this.server = server;
        this.clientSocket = clientSocket;
    }


    public void run() {
        try{
            HandleClient(); // this method is only ever called when a thread is started
            System.out.println("Running HandleClient...");
        } catch (IOException e){
            e.printStackTrace();
        } catch (InterruptedException e){
            e.printStackTrace();
        }
    }

    

    private void HandleClient() throws IOException, InterruptedException{
        System.out.println("Server is still alive");

        this.input = clientSocket.getInputStream();
        this.output = clientSocket.getOutputStream();

        BufferedReader reader = new BufferedReader(new InputStreamReader(input));
        
        String line; 

        while((line=reader.readLine())!=null){
            String [] tokens = line.split(" ");
            String cmd = tokens[0];
            System.out.println("In handle client...");
            if (tokens !=null && tokens.length>0){
                System.out.println("Looking at tokens...");
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
                else if ("img".equalsIgnoreCase(cmd)){
                 //  System.out.println(tokens[0] + " " + tokens[1] + " " + tokens[2] + " "+ tokens[3]);
                    String[] imgTokens = line.split(" ", 4);
                    //System.out.println(line);
                    handleImage(imgTokens);
                }
                else{
                    String msg = "Unknown " + cmd + "\n";
                    output.write(msg.getBytes());   
                } 
            }
                     
        }
    }

    private void handleImage(String[] tokens) {
        String sendTo = tokens[1];
        String file = tokens[3];
        String caption= tokens[2];

        List<ServerWorker> workerList = server.getWorkerList();
        for(ServerWorker worker: workerList){
            if(sendTo.equalsIgnoreCase(worker.getLogin())){
                String outMsg = "img "+ login +" "+ file + " "+caption+ "\n";
                try {
                    worker.send(outMsg);
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }
        /*
        try {
            System.out.println("We're In!");
           // decodeString(tokens);
          //  encodeString(tokens);
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }*/
    }

    private void encodeString(String[] tokens) throws Exception {
        String caption = tokens[3];
        FileInputStream fis = new FileInputStream("/Users/aneledlamini/Desktop/NIS/sunset.jpg");
        System.out.println("Still sending to client...");
        BufferedImage bImage = ImageIO.read(new File("/Users/aneledlamini/Desktop/NIS/sunset.jpg"));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ImageIO.write(bImage, "jpg", bos);
        System.out.println("Still sending to client...");
        byte[] b = bos.toByteArray();
        fis.read(b, 0, b.length); // reading all bytes of file
        List<ServerWorker> workerList = server.getWorkerList();
        for(ServerWorker worker: workerList){
            if(!login.equals(worker.getLogin())){
                try{
                    String cmd = "img " + login + " " + Base64.getEncoder().encodeToString(b) + " " + caption + "\n";
                    System.out.println("Still sending to client...");
                    worker.send(cmd);
                    System.out.println("Sent to worker...");
                }
                catch(IOException e){
                    e.printStackTrace();
                }
            }
        }
    }

    // tokens = 4
    private void decodeString (String [] tokens) throws Exception{
        System.out.println("Recieving from client...");
        InputStream is = clientSocket.getInputStream();
        FileOutputStream fos = new FileOutputStream("/Users/aneledlamini/Desktop/NIS/sunset.jpg"); // where the new file will be saved
        try{
            byte[] b = Base64.getDecoder().decode(new String(tokens[2]).getBytes("UTF-8"));
            System.out.println("Recieving from client...");
           // System.out.println(new String (b, StandardCharsets.UTF_8) + "\n");
            is.read(b,0,b.length); //read bytes 
            System.out.println("Ses'fikile...");
            fos.write(b,0,b.length); // write bytes to new file
            System.out.println("Received!");
            System.out.println(tokens[3]);
        }catch(Exception e){
            e.printStackTrace();
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
        if(tokens.length ==3){
            String login = tokens[1];
            String password = tokens[2];

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

    /*private void handleMessage(String [] tokens) {
        String sendTo = tokens [1];
        String msg = tokens[2];

        List <ServerWorker> workerList = server.getWorkerList();
        for(ServerWorker worker: workerList){
            //if sendTo.equalsIgnoreCase()
        }
    }*/
}
