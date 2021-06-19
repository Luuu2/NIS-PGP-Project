package ChatClient;

import java.awt.image.BufferedImage;
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
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.imageio.ImageIO;

public class Client {
    private final String serverName;
    private final int serverPort;
    private OutputStream serverOut;
    private InputStream serverIn;
    private BufferedReader bufferIn;
    private final String userName;
    private final String password;
    private Socket socket;
    private Scanner scanner;
    private DataInputStream dis;
    private ObjectInputStream ois;
    private String cipher;
    private SecretKey key;
    private IvParameterSpec iv;
    String receiver;
    String sender;

    public Client(String serverName, int serverPort, String userName, String password) {
        this.serverName = serverName;
        this.serverPort = serverPort;
        this.userName = userName;
        this.password = password;
    }

    public static void main(String[] args) throws ClassNotFoundException {
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

    public boolean connect() {
        try {
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
        String cmd = "login " + userName + " " + password + "\n";
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

    private void msgReader() {
        Thread t = new Thread() {
            public void run() {
                while (true) {
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
                                // System.out.println("");
                                //String captionFile = new String(tokens[2]); // "caption space base64Image"
                                String ci = tokens[2];
                                //cipher = ci.getBytes();
                                String plainText = decrypt("AES/CBC/PKCS5Padding", cipher, key, iv);
                                String [] imgCap = plainText.split(" ",2);
                                decodeString(imgCap);
                               // decodeString(captionFile.split(" ")); // new list format: [caption, base64Image]
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        } else {
                            System.out.println(response + "\n");
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
                    String[] tokens = message.split(" ", 3);
                    if (message.equalsIgnoreCase("quit") || message.equalsIgnoreCase("logoff")) {
                        String cmd = "quit";
                        try {
                            serverOut.write(cmd.getBytes());
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                        break;
                    } else if (tokens[0].equalsIgnoreCase("img")) {
                        try {
                            cipher = encrypt("AES/CBC/PKCS5Padding", encodeString(tokens, receiver), key, iv);
                            String cmd = "img" + receiver + " " + cipher + "\n";
                            serverOut.write(cmd.getBytes());

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
        File f = new File(tokens[2]); // file to be taken in (image path)
        FileInputStream fis = new FileInputStream(f); // taking in file
        System.out.println("Still sending to server....");
        byte imageData[] = new byte[(int) f.length()];
        fis.read(imageData);
        String base64Image = Base64.getEncoder().encodeToString(imageData);
        /*
         * BufferedImage bImage = ImageIO.read(new File(tokens[2]));
         * ByteArrayOutputStream bos = new ByteArrayOutputStream();
         * ImageIO.write(bImage, "jpg", bos); byte[] b = bos.toByteArray(); fis.read(b,
         * 0, b.length); // reading all bytes of file
         */
        System.out.println("Still sending to server....");
        // String cmd = "img " + receiver + " " + Base64.getEncoder().encodeToString(b)
        // + " " + caption + "\n";
        String cmd = "img " + receiver + " " + base64Image + " " + caption + "\n";
        String encodedImgCap = base64Image + " " + caption;
        serverOut.write(cmd.getBytes());
        System.out.println("Sent to server");
        return encodedImgCap;
        // System.out.println(cmd);

    }

    // token format from server: [baseImage,caption]
    private void decodeString(String[] tokens) throws Exception { // tokens format: ["img",reciever,caption base64Image]
                                                                  // -- takes in the caption + baseimage as one
        System.out.println("Recieving from server...");
        FileOutputStream fos = new FileOutputStream("///home/d/dlmsil008/Desktop/NIS/sunset.jpg"); // where the new
                                                                                                    // file
                                                                                                    // will be saved
        try {
            // String captionFile = new String(tokens[2]).split(" "));
            String file = new String(tokens[1]).replaceAll(" +", "+");
            byte[] b = Base64.getDecoder().decode(file);
            System.out.println("Recieving from server...");
            // serverIn.read(b,0,b.length); //read bytes, i think it reads in what is sent
            // after the above line e.g "hi" hence reads nothing into the file
            fos.write(b); // write bytes to new file
            System.out.println("Received!");
            System.out.println(sender +"sent an image with the caption "+tokens[0]);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // encryting Base64 + caption String
    public static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    // dencryting Base64 + caption String
    public static String decrypt(String algorithm, String cipherText, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    // Lulu encde string method --- this has been implemented with the encodeString
    // method
    /*
     * private String encodeFileToBase64Binary(File file) { String encodedfile =
     * null; try { FileInputStream fileInputStreamReader = new
     * FileInputStream(file); byte[] bytes = new byte[(int) file.length()];
     * fileInputStreamReader.read(bytes); encodedfile =
     * Base64.getEncoder().encodeToString(bytes); fileInputStreamReader.close(); }
     * catch (FileNotFoundException e) { // TODO Auto-generated catch block
     * e.printStackTrace(); } catch (IOException e) { // TODO Auto-generated catch
     * block e.printStackTrace(); }
     * 
     * return encodedfile; }
     */

}

/*
 * public class Client { private final String serverName; private final int
 * serverPort; private OutputStream serverOut; private Socket socket; private
 * InputStream serverIn; private BufferedReader bufferIn;
 * 
 * private ArrayList<UserStatusListener> listeners = new ArrayList<>(); private
 * ArrayList<MessageListener> messages = new ArrayList<>();
 * 
 * public Client(String serverName, int serverPort){ this.serverName =
 * serverName; this.serverPort = serverPort; }
 * 
 * public static void main(String [] args) throws IOException { Client client =
 * new Client("localhost", 8818);
 * 
 * client.addListener(new UserStatusListener(){
 * 
 * @Override public void online(String login) {
 * System.out.println("Online: "+login);
 * 
 * }
 * 
 * @Override public void offline(String login) {
 * System.out.println("Offline: "+login); }
 * 
 * });
 * 
 * client.addMessageListeners(new MessageListener(){
 * 
 * @Override public void onMessage(String fromLogin, String msgBody) {
 * System.out.println("You have a message from "+ fromLogin);
 * System.out.println("Message: "+ msgBody);
 * 
 * }
 * 
 * });
 * 
 * if(!client.connect()){ System.err.println("Connect failed."); } else{
 * System.out.println("Connect successful.");
 * 
 * if(client.login("guest", "guest")){ System.out.println("Login Successful");
 * client.msg("jim", "Hello World"); } else{ System.out.println("Login Failed");
 * }
 * 
 * //client.logOff();
 * 
 * } }
 * 
 * private void msg(String sendto, String msgbody) throws IOException { String
 * cmd = "msg " + sendto + " "+ msgbody +"\n"; serverOut.write(cmd.getBytes());
 * }
 * 
 * private void logOff() throws IOException { String cmd = "logoff\n";
 * serverOut.write(cmd.getBytes());
 * 
 * }
 * 
 * private boolean login(String userName, String password) throws IOException {
 * String cmd = "login "+ userName + " "+ password+"\n";
 * serverOut.write(cmd.getBytes()); String response = bufferIn.readLine();
 * System.out.println("Response Line: "+ response);
 * if("ok login".equalsIgnoreCase(response)){ startMessageReader(); return true;
 * } else{ return false; } }
 * 
 * private void startMessageReader() { Thread t = new Thread(){ public void
 * run(){ readMessageLoop(); } }; t.start(); }
 * 
 * protected void readMessageLoop() { try{ String line; while((line =
 * bufferIn.readLine())!=null){ String [] tokens = line.split(" ", 3);
 * if(tokens!=null & tokens.length>0){ String cmd = tokens[0]; if
 * ("online".equalsIgnoreCase(cmd)){ handleOnline(tokens); } else if
 * ("offline".equalsIgnoreCase(cmd)){ handleOffline(tokens); } else if
 * ("msg".equalsIgnoreCase(cmd)){ handleMessage(tokens); }
 * 
 * }
 * 
 * } } catch (Exception e){ e.printStackTrace(); try { socket.close(); } catch
 * (IOException e1) { e1.printStackTrace(); } } }
 * 
 * private void handleMessage(String [] tokens) { String login = tokens [1];
 * String msgBody = tokens[2];
 * 
 * for(MessageListener message : messages){ message.onMessage(login, msgBody); }
 * }
 * 
 * private void handleOffline(String[] tokens) { String login = tokens [1];
 * for(UserStatusListener listener: listeners){ listener.offline(login); } }
 * 
 * private void handleOnline(String [] tokens) { String login = tokens [1];
 * for(UserStatusListener listener: listeners){ listener.online(login); } }
 * 
 * private boolean connect() { try { this.socket = new Socket(serverName,
 * serverPort); System.out.println("Client port is "+socket.getLocalPort());
 * this.serverOut = socket.getOutputStream(); this.serverIn =
 * socket.getInputStream(); this.bufferIn = new BufferedReader(new
 * InputStreamReader(serverIn)); return true; } catch (IOException e) {
 * e.printStackTrace(); } return false; }
 * 
 * public void addListener(UserStatusListener userListener){
 * listeners.add(userListener); } public void removeListener(UserStatusListener
 * userListener){ listeners.remove(userListener); }
 * 
 * public void addMessageListeners(MessageListener message){
 * messages.add(message); }
 * 
 * public void removeMessageListeners(MessageListener message){
 * messages.remove(message); } }
 */
