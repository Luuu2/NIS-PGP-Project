package ChatServer;

import java.io.File;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.security.cert.Certificate;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;
import java.security.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class UserClient{
    private static final String BC_PROVIDER = "BC";
    private final Certificate certificate;
    private final String userName;
    private final byte[] SHAedPW;

    public UserClient(String userName, String password, Certificate certificate){
        this.certificate = certificate;
        this.userName = userName;
        this.SHAedPW = generateSHA(userName, password);
    }

    private byte[] generateSHA(String user, String pw){
        Security.addProvider(new BouncyCastleProvider());
        byte[] hPassword = new byte[0];
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256", BC_PROVIDER);
            md.update(md.digest( (user + " " + pw).getBytes(StandardCharsets.UTF_8) ));
            hPassword = md.digest( pw.getBytes(StandardCharsets.UTF_8) );
        }catch(Exception e){
            e.printStackTrace();
        }
        return hPassword;
    }

    public boolean checkSHA() throws FileNotFoundException{
        File sct = new File("ServerCoolTings.txt");
        Scanner scan = new Scanner(sct);
        while(scan.hasNextLine()){
            String line = scan.nextLine().replace("\n", "");
            if(line.startsWith(this.userName)){
                String shaValue = line.split(":")[1];
                String stringSHAedPW = Arrays.toString( SHAedPW ).replace(" ", "").replace("]", "").replace("[", "");
                scan.close();
                return shaValue.equals(stringSHAedPW);
            }

        }
        scan.close();
        return false;

    }
    /*
    public static void main(String args[]){
        String u = args[0];
        String p = args[1];
        UserClient uc = new UserClient(u, p, null);
        try{
            System.out.println(uc.checkSHA());
        } catch(Exception e ){}
    }
    */
        
}