package CAServer;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;

// // Sign the new KeyPair with the root cert Private Key
// ContentSigner csrContentSigner = csrBuilder.build(rootKeyPair.getPrivate());
/// PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

public class Server {
    private final int serverPort;
    private ArrayList<ServerWorker> workerList = new ArrayList<>();
    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    

    public static void main(String[] args) {
        int port = 8818;
        Server server = new Server(port);
        server.run();
        
    }

    static KeyStore ImportKeyPairFromKeystoreFile(String fileName, Certificate certificate, String alias, String fileName, String storeType, String storePass) throws Exception {
        FileInputStream keyStoreOs = new FileInputStream(fileName);
        KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);
        //KeyStore sslKeyStore = KeyStore.getInstance(storeType, BC_PROVIDER);
        //sslKeyStore.load(null, null);
        //sslKeyStore.setKeyEntry(alias, keyPair.getPrivate(),null, new Certificate[]{certificate});
        
       // sslKeyStore.store(keyStoreOs, storePass.toCharArray());
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
