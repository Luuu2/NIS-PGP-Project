package ChatServer;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.cert.Certificate;
import java.security.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class Server {
    private final int serverPort;
    //private ArrayList<ServerWorker> workerList = new ArrayList<>();
    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private Certificate certificate;
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
        //server.run(); 
    }

    public Server (int serverPort){
        this.serverPort = serverPort;
        try{
            importKeyPairFromKeystoreFile("PGP-icert.pfx", "PGP-icert.cer", "PKCS12");
        } catch(Exception e){
            e.printStackTrace();
        }   
    }
/*
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
        //workerList.remove(serverWorker);
        int i = 0;
    }
    */
}
