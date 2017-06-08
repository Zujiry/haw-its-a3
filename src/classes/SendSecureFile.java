package classes;

import Utility.Util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;

import java.security.*;


/**
 * Created by Zujiry on 31/05/2017.
 */
public class SendSecureFile {
    public static void main(String[] args){

    }

    public SendSecureFile(String privKeyFile, String pubKeyFile, String input, String output){
        PrivateKey priv = null;
        PublicKey pub = null;
        SecretKey aesKey;
        Signature signature;
        Cipher cipher;
        File file;
        try {
            //a) Einlesen eines privaten RSA‐Schlüssels (.prv) aus einer Datei gemäß Aufgabenteil 1. 
            //b) Einlesen eines öffentlichen RSA‐Schlüssels (.pub) aus einer Datei gemäß Aufgabenteil 1. 
            priv = Util.loadPrivKey(privKeyFile);
            pub = Util.loadPubKey(pubKeyFile);

            //c) Erzeugen eines geheimen Schlüssels für den AES‐Algorithmus mit der Schlüssellänge 128 Bit 
            aesKey = generateAESKey();

            //d) Erzeugung einer Signatur für den geheimen Schlüssel aus c) mit dem privaten RSA‐Schlüssel 
            //   (Algorithmus: „SHA256withRSA“) 
            signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(priv);
            signature.update(aesKey.getEncoded());
            byte[] signatureBytes = signature.sign();

            //e) Verschlüsselung des geheimen Schlüssels aus c) mit dem öffentlichen RSA‐Schlüssel (Algorithmus: „RSA“) 
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pub);
            byte[] cipherData = cipher.update(aesKey.getEncoded());
            byte[] cipherRest = cipher.doFinal();
            byte[] cipherText = Util.concatenate(cipherData,cipherRest);

            // f) Einlesen einer Dokumentendatei, Verschlüsseln der Dateidaten mit dem symmetrischen AES‐
            // Algorithmus (geheimer Schlüssel aus c) im Counter‐Mode („CTR“)
            File inputFile = new File(input);
            FileInputStream fileInputStream = new FileInputStream(inputFile);
            Cipher inputCipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
            inputCipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] readInput = new byte[8];
            int len;
            byte[] inputCipherFile = new byte[0];
            while ((len = fileInputStream.read(readInput)) > 0) {
                inputCipherFile = Util.concatenate(inputCipherFile,inputCipher.update(readInput.clone()));
            }
            byte[] inputCipherFinal = inputCipher.doFinal();
            byte[] inputCipherText = Util.concatenate(inputCipherFile,inputCipherFinal);

            // Erzeugen einer Ausgabedatei
            File outputFile = new File(output);
            FileOutputStream fileOutputStream = new FileOutputStream(outputFile);
            DataOutputStream dataOutputStream = new DataOutputStream(fileOutputStream);
            /*
            1. Länge des verschlüsselten geheimen Schlüssels (integer) 
            2. Verschlüsselter geheimer Schlüssel (Bytefolge) 
            3. Länge der Signatur des geheimen Schlüssels (integer) 
            4. Signatur des geheimen Schlüssels (Bytefolge) 
            5. Länge der algorithmischen Parameter des geheimen Schlüssels 
            6. Algorithmische Parameter des geheimen Schlüssels (Bytefolge) 
            7. Verschlüsselte Dateidaten (Ergebnis von f) (Bytefolge) 
            */
            dataOutputStream.writeInt(cipherText.length);
            dataOutputStream.write(cipherText,0,cipherText.length);
            dataOutputStream.writeInt(signatureBytes.length);
            dataOutputStream.write(signatureBytes,0,signatureBytes.length);
            dataOutputStream.writeInt(inputCipher.getParameters().getEncoded().length);
            dataOutputStream.write(inputCipher.getParameters().getEncoded());
            dataOutputStream.write(inputCipherText,0,inputCipherText.length);
            dataOutputStream.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private SecretKey generateAESKey() throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        return kgen.generateKey();
    }



}
