package ChatServer;

import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.imageio.ImageIO;

import java.io.InputStreamReader;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamException;
import java.io.OutputStream;
import java.awt.image.BufferedImage;
import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

//import org.apache.commons.lang3.StringUtils;

public class ServerWorker extends Thread  {
    private final Socket clientSocket;
    private final Server server;
    private String login = null;
    private OutputStream output;
    private InputStream input;
    private SecretKey sharedKey;
    ObjectOutputStream objectOutputStream;
    private DataOutputStream dos;
    private IvParameterSpec sharedIv;
    

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

    private void HandleClient() throws IOException, InterruptedException {
        System.out.println("Server is still alive");

        this.input = clientSocket.getInputStream();
        this.output = clientSocket.getOutputStream();
        this.objectOutputStream = new ObjectOutputStream(clientSocket.getOutputStream());
        this.dos = new DataOutputStream(output);

        BufferedReader reader = new BufferedReader(new InputStreamReader(input));

        String line;

        while ((line = reader.readLine()) != null) {
            String[] tokens = line.split(" ",3);
            String cmd = tokens[0];
            System.out.println("In handle client...");
            if (tokens != null && tokens.length > 0) {
                System.out.println("Looking at tokens...");
                if ("quit".equalsIgnoreCase(cmd) || "logoff".equalsIgnoreCase(cmd)) {
                    handleLogoff();
                    break;
                } else if ("login".equalsIgnoreCase(cmd)) {
                    handleLogin(output, tokens);
                    System.out.println(sharedKey);
                    System.out.println(sharedIv);
                    /*try {
                        //generateKey(login);
                        //generateIv(login);
                    } catch (NoSuchAlgorithmException e) {
                        // TODO Auto-generated catch block
                        e.printStackTrace();
                    }*/
                    

                } else if ("msg".equalsIgnoreCase(cmd)) {
                    String[] msgTokens = line.split(" ", 3);
                    handleMessage(msgTokens);
                } else if ("img".equalsIgnoreCase(cmd)) {
                    String[] imgTokens = line.split(" ", 3);
                    handleImage(imgTokens);
                } else {
                    String msg = "Unknown " + cmd + "\n";
                    output.write(msg.getBytes());
                }
            }

        }
    }

    public void generateKey(String name) throws NoSuchAlgorithmException { // 256 bit key for 14 rounds
        String sendTo = name; // reciever

        /*KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);
        sharedKey = keyGenerator.generateKey();
        */
       // byte [] encoded = sharedKey.getEncoded();
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

        //byte[] iv = new byte[16];
        //new SecureRandom().nextBytes(iv);
       // ByteArrayOutputStream bos = new ByteArrayOutputStream();

        List<ServerWorker> workerList = server.getWorkerList();
        for (ServerWorker worker : workerList) {
            if (sendTo.equalsIgnoreCase(worker.getLogin())) {
                try {
                    //IvParameterSpec Iv = new IvParameterSpec(iv);
                   // objectOutputStream.flush();
                    //objectOutputStream.reset();
                    //bos.write(Iv.getIV());
                    output.write(sharedIv.getIV());
                   // objectOutputStream.writeObject(Iv);
                    
                } catch (IOException e) {
                    // TODO Auto-generated catch block
                    e.printStackTrace();
                }
            }
        }

    }

    private void handleImage(String[] tokens) {
        String sendTo = tokens[1];
        String cipher = tokens[2];

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
        /*
         * try { System.out.println("We're In!"); decodeString(tokens);
         * encodeString(tokens); } catch (Exception e) { // TODO Auto-generated catch
         * block e.printStackTrace(); }
         */
    }

    private void encodeString(String[] tokens) throws Exception { // token format:
        String caption = tokens[3];
        FileInputStream fis = new FileInputStream("///home/d/dlmsil008/Desktop/NIS/sunset.jpg");
        System.out.println("Still sending to client...");
        BufferedImage bImage = ImageIO.read(new File("///home/d/dlmsil008/Desktop/NIS/sunset.jpg"));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ImageIO.write(bImage, "jpg", bos);
        System.out.println("Still sending to client...");
        byte[] b = bos.toByteArray();
        fis.read(b, 0, b.length); // reading all bytes of file
        List<ServerWorker> workerList = server.getWorkerList();
        for (ServerWorker worker : workerList) {
            if (!login.equals(worker.getLogin())) {
                try {
                    String cmd = "img " + login + " " + caption + " " + Base64.getEncoder().encodeToString(b) + "\n";
                    System.out.println("Still sending to client...");
                    worker.send(cmd);
                    System.out.println("Sent to worker...");
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    // tokens format: [img,reciever,encodedImage,caption]
    private void decodeString(String[] tokens) throws Exception {
        System.out.println("Recieving from client...");
        FileOutputStream fos = new FileOutputStream("/Users/aneledlamini/Desktop/NIS/sunset1.jpg"); // where the new
                                                                                                    // file will be
                                                                                                    // saved
        try {
            // String captionFile = new String(tokens[2]).split(" "));
            String file = new String(tokens[2]).replaceAll(" +", "+");
            byte[] b = Base64.getDecoder().decode(file);
            System.out.println("Recieving from client...");
            // serverIn.read(b,0,b.length); //read bytes, i think it reads in what is sent
            // after the above line e.g "hi" hence reads nothing into the file
            fos.write(b); // write bytes to new file
            System.out.println("Received!");
            System.out.println(tokens[3]);
        } catch (Exception e) {
            e.printStackTrace();
        }
        /*
         * try{ byte[] b = Base64.getDecoder().decode(new
         * String(tokens[2]).getBytes("UTF-8"));
         * System.out.println("Recieving from client..."); // System.out.println(new
         * String (b, StandardCharsets.UTF_8) + "\n"); is.read(b,0,b.length); //read
         * bytes System.out.println("Ses'fikile..."); fos.write(b,0,b.length); // write
         * bytes to new file System.out.println("Received!");
         * System.out.println(tokens[3]); }catch(Exception e){ e.printStackTrace(); }
         */
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

    private void handleLogin(OutputStream output, String[] tokens) throws IOException {
        if (tokens.length == 3) {
            String login = tokens[1];
            String password = tokens[2];

            if (login.equals("Alice") && password.equals("Alice") || login.equals("Bob") && password.equals("Bob")) {
                String msg = "ok login\n";
                output.write(msg.getBytes());
                this.login = login;
                System.out.println("User logged in successfully:" + login);

                String onlineMsg = "online " + login + "\n";
                List<ServerWorker> workerList = server.getWorkerList();

                // send current user all other online logins
                for (ServerWorker worker : workerList) {
                    if (worker.getLogin() != null) {
                        if (!login.equals(worker.getLogin())) {
                            String msg2 = "online " + worker.getLogin() + '\n';
                            send(msg2);
                        }
                    }

                }
                // send other online users current user's status
                for (ServerWorker worker : workerList) {
                    if (!login.equals(worker.getLogin())) {
                        worker.send(onlineMsg);
                    }
                }
            } else {
                String msg = "error login\n";
                System.out.println("Unsuccessful login attempt");
                output.write(msg.getBytes());
            }
        }
    }

    private void send(String msg) throws IOException {
        if (login != null) {
            output.write(msg.getBytes());
        }
    }

    /*
     * private void handleMessage(String [] tokens) { String sendTo = tokens [1];
     * String msg = tokens[2];
     * 
     * List <ServerWorker> workerList = server.getWorkerList(); for(ServerWorker
     * worker: workerList){ //if sendTo.equalsIgnoreCase() } }
     */
}
