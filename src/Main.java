import classes.RSAKeyCreation;
import classes.ReceiveSecureFile;
import classes.SendSecureFile;

/**
 * Created by Zujiry on 31/05/2017.
 */
public class Main {
    public static void main(String args[]){
        String filename = "Name";
        new RSAKeyCreation(filename);
        new SendSecureFile(System.getProperty("user.dir") + "\\src\\" + filename + ".prv",
                System.getProperty("user.dir") + "\\src\\" +filename + ".pub",
                System.getProperty("user.dir") + "\\src\\TestFileIn",
                System.getProperty("user.dir") + "\\src\\TestFileOut");
        new ReceiveSecureFile(System.getProperty("user.dir") + "\\src\\" + filename + ".prv",
                System.getProperty("user.dir") + "\\src\\" +filename + ".pub",
                System.getProperty("user.dir") + "\\src\\TestFileOut",
                System.getProperty("user.dir") + "\\src\\files\\Outputfile.pdf"
        );


        //Aufgabe 4
        filename = "TestKey";
        new RSAKeyCreation(filename);
        new SendSecureFile(System.getProperty("user.dir") + "\\src\\" + filename + ".prv",
                System.getProperty("user.dir") + "\\src\\" +filename + ".pub",
                System.getProperty("user.dir") + "\\src\\files\\ITSAufgabe3.pdf",
                System.getProperty("user.dir") + "\\src\\TestFileOut"
        );
        new ReceiveSecureFile(System.getProperty("user.dir") + "\\src\\" + filename + ".prv",
                System.getProperty("user.dir") + "\\src\\" +filename + ".pub",
                System.getProperty("user.dir") + "\\src\\TestFileOut",
                System.getProperty("user.dir") + "\\src\\files\\Outputfile.pdf"
        );
    }
}
