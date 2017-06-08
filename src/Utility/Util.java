package Utility;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * Created by Zujiry on 31/05/2017.
 */
public class Util {
    public static PrivateKey loadPrivKey(String filename) throws Exception {
        File inputFile = new File(filename);
        FileInputStream fileInputStream = new FileInputStream(inputFile);
        DataInputStream dataInputStream = new DataInputStream((fileInputStream));

        int nameLength = dataInputStream.readInt();
        byte[] name = new byte[nameLength];
        dataInputStream.read(name);

        int keyLength = dataInputStream.readInt();
        byte[] key = new byte[keyLength];
        dataInputStream.read(key);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(key);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    public static PublicKey loadPubKey(String filename) throws Exception {
        File inputFile = new File(filename);
        FileInputStream fileInputStream = new FileInputStream(inputFile);
        DataInputStream dataInputStream = new DataInputStream((fileInputStream));

        int nameLength = dataInputStream.readInt();
        byte[] name = new byte[nameLength];
        dataInputStream.read(name);

        int keyLength = dataInputStream.readInt();
        byte[] key = new byte[keyLength];
        dataInputStream.read(key);

        X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }

    /**
     * Concatenate two byte arrays
     */
    public static byte[] concatenate(byte[] ba1, byte[] ba2) {
        int len1 = ba1.length;
        int len2 = ba2.length;
        byte[] result = new byte[len1 + len2];

        // Fill with first array
        System.arraycopy(ba1, 0, result, 0, len1);
        // Fill with second array
        System.arraycopy(ba2, 0, result, len1, len2);

        return result;
    }
}
