package ChatServer;

import java.net.Socket;
import java.util.List;

import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
//import org.apache.commons.lang3.StringUtils;


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

    private void HandleClient() throws IOException, InterruptedException{
        System.out.println("Server is still alive");

        InputStream input = clientSocket.getInputStream();
        this.output = clientSocket.getOutputStream();

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
