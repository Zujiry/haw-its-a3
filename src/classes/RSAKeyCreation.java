package classes;

import java.io.*;
import java.security.*;

/**
 * Created by Zujiry on 31/05/2017.
 */
public class RSAKeyCreation {
    private File publicKey;
    private File privateKey;

    public RSAKeyCreation(String name){
        this.publicKey = new File(System.getProperty("user.dir")+ "\\src\\" + name + ".pub");
        this.privateKey = new File(System.getProperty("user.dir")+ "\\src\\" + name + ".prv");

        Key pub = null;
        Key priv = null;

        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            SecureRandom random = new SecureRandom();
            keyGen.initialize(2048, random);
            KeyPair kp = keyGen.generateKeyPair();
            pub = kp.getPublic();
            priv = kp.getPrivate();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        createKeyFile(name,pub, ".pub");
        createKeyFile(name,priv,".prv");
    }


    private void createKeyFile(String name, Key key, String ending) {
        // OutputStream to write to File
        FileOutputStream outputStream = null;
        File file = new File(System.getProperty("user.dir")+ "\\src\\" + name + ending);
        try {
            outputStream = new FileOutputStream(file);
            DataOutputStream dataOutputStream = new DataOutputStream(outputStream);
            // Length of user name
            dataOutputStream.writeInt(name.length());
            // Name
            dataOutputStream.write(name.getBytes(),0,name.length());
            // Length of public key
            dataOutputStream.writeInt(key.getEncoded().length);
            // PublicKey
            dataOutputStream.write(key.getEncoded(),0,key.getEncoded().length);
            dataOutputStream.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
