package ChatServer;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;

public class Server {
    private final int serverPort;
    private ArrayList<ServerWorker> workerList = new ArrayList<>();
    
    

    public static void main(String[] args) {
        int port = 8818;
        Server server = new Server(port);
        server.run();
        
    }

    public Server (int serverPort){
        this.serverPort = serverPort;
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
    }
}
