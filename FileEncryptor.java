import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Scanner;

public class FileEncryptor {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter the path of the file to encrypt: ");
        String filePath = scanner.nextLine();

        System.out.print("Enter the encryption password: ");
        String password = scanner.nextLine();

        System.out.print("Enter the output file path: ");
        String outputPath = scanner.nextLine();

        try {
            SecretKey secretKey = deriveKey(password);
            encryptFile(filePath, secretKey, outputPath);
            System.out.println("File encrypted successfully.");
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
        }
    }

    private static SecretKey deriveKey(String password) throws NoSuchAlgorithmException {
        // Simplified key derivation for demonstration purposes
        byte[] keyBytes = password.getBytes();
        byte[] key = new byte[16]; // 128-bit key for AES-256
        System.arraycopy(keyBytes, 0, key, 0, Math.min(keyBytes.length, key.length));
        return new SecretKeySpec(key, "AES");
    }

    public static void encryptFile(String filePath, SecretKey secretKey, String outputPath) throws GeneralSecurityException, IOException {
        Path inputFile = Paths.get(filePath);
        if (!Files.exists(inputFile)) {
            System.out.println("The input file does not exist.");
            return;
        }

        Path outputFile = Paths.get(outputPath);
        if (Files.exists(outputFile)) {
            System.out.println("The output file already exists. Choose a different path.");
            return;
        }

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        try (FileInputStream fis = new FileInputStream(filePath);
             FileOutputStream fos = new FileOutputStream(outputPath);
             CipherOutputStream cos = new CipherOutputStream(fos, cipher)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                cos.write(buffer, 0, bytesRead);
            }
        }
    }
}
