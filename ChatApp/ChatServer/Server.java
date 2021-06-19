package ChatServer;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Server {
    private final int serverPort;
    private ArrayList<ServerWorker> workerList = new ArrayList<>();
    private SecretKey sharedKey;
    private IvParameterSpec sharedIv;
    

    public static void main(String[] args) throws NoSuchAlgorithmException {
        int port = 8818;
        Server server = new Server(port);
        server.run();
        
    }

    public Server(int serverPort) {
        this.serverPort = serverPort;
    }

    public List<ServerWorker> getWorkerList() {
        return workerList;
    }

    public void run() throws NoSuchAlgorithmException {
        generateKey();
        generateIv();
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
}
