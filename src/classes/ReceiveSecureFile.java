package classes;

import Utility.Util;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;


/**
 * Created by Zujiry on 31/05/2017.
 */
public class ReceiveSecureFile {
    public static void main(String[] args){
        if(args.length != 4) {
            System.out.println("Usage: ReceiveSecureFile <Name of private key file> <Name of public key file> <Encrypted secure file> <Output file>");

        }

        String privKeyFile = args[0];
        String pubKeyFile = args[1];
        String input = args[2];
        String output = args[3];

        new ReceiveSecureFile(privKeyFile,pubKeyFile,input,output);
    }

    public ReceiveSecureFile(String privKeyFile, String pubKeyFile, String input, String output){
        PrivateKey priv = null;
        PublicKey pub = null;
        try {
            //a) Einlesen eines öffentlichen RSA‐Schlüssels aus einer Datei gemäß Aufgabenteil 1. 
            priv = Util.loadPrivKey(privKeyFile);
            //b) Einlesen eines privaten RSA‐Schlüssels aus einer Datei gemäß Aufgabenteil 1. 
            pub = Util.loadPubKey(pubKeyFile);
            //c) Einlesen einer .ssf‐Datei gemäß Aufgabenteil 2, Entschlüsselung des geheimen Schlüssels mit 
            //dem privaten RSA‐Schlüssel
            File inputFile = new File(input);
            FileInputStream fileInputStream = new FileInputStream(inputFile);
            DataInputStream dataInputStream = new DataInputStream((fileInputStream));
            // Read AES key
            int keyLength = dataInputStream.readInt();
            byte[] aesKey = new byte[keyLength];
            dataInputStream.read(aesKey);
            // Read Signature
            int signatureLength =  dataInputStream.readInt();
            byte[] signatureBytes = new byte[signatureLength];
            dataInputStream.read(signatureBytes);
            // Read AlgorithmParameters
            int rsaParamsLength = dataInputStream.readInt();
            byte[] rsaParams = new byte[rsaParamsLength];
            dataInputStream.read(rsaParams);

            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE,priv);
            byte[] decryptedAesKey = cipher.doFinal(aesKey);

            // Entschlüsselung der Dateidaten mit dem geheimen Schlüssel (AES im Counter‐Mode) – mit Anwendung der übermittelten algorithmischen Parameter – sowie 
            //Erzeugung einer Klartext‐Ausgabedatei.
            SecretKeySpec skspec = new SecretKeySpec(decryptedAesKey, "AES");

            // Algorithmische Parameter aus Parameterbytes ermitteln (z.B. IV)
            AlgorithmParameters algorithmParms = AlgorithmParameters
                    .getInstance("AES");
            algorithmParms.init(rsaParams);

            Cipher inputCipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
            inputCipher.init(Cipher.DECRYPT_MODE,skspec,algorithmParms);

            byte[] readInput = new byte[8];
            int len;
            byte[] inputCipherFile = new byte[0];
            while ((len = fileInputStream.read(readInput)) > 0) {
                inputCipherFile = Util.concatenate(inputCipherFile,inputCipher.update(readInput.clone()));
            }
            byte[] inputCipherFinal = inputCipher.doFinal();

            // Write decrypted out
            File outputFile = new File(output);
            FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
            DataOutputStream dataOutputStream = new DataOutputStream(fileOutputStream);
            dataOutputStream.write(inputCipherFile);

            dataInputStream.close();
            dataOutputStream.close();
            //d) Überprüfung der Signatur für den geheimen Schlüssel aus c) mit dem öffentlichen RSA‐Schlüssel 
            //(Algorithmus: „SHA256withRSA“) 
            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initVerify(pub);
            // Echter AES Key, der auch verschlüsselt wurde
            signature.update(decryptedAesKey);
            if(signature.verify(signatureBytes)){
                System.out.println("Signature Verified");
            } else {
                System.out.println("Signature could not be verified");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
