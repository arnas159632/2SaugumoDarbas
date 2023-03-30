import javax.crypto.*;
import javax.crypto.spec.*;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;


public class EncryptionCBC {
    private SecretKey key;
    private int KEY_SIZE = 256;
    private Cipher encryptionCipher;
    private Cipher decryptionCipher;

    public void init(String secretKey, String cipherMode) throws Exception {
        byte[] keyBytes = secretKey.getBytes(StandardCharsets.UTF_8);
        key = new SecretKeySpec(Arrays.copyOf(keyBytes, KEY_SIZE / 8), "AES");

        String cipherTransform;
        if (cipherMode.equals("ECB")) {
            cipherTransform = "AES/" + cipherMode + "/NoPadding";
            encryptionCipher = Cipher.getInstance(cipherTransform);
            encryptionCipher.init(Cipher.ENCRYPT_MODE, key);


        } else {
            SecureRandom secureRandom = new SecureRandom();
            byte[] ivBytes = new byte[16];
            secureRandom.nextBytes(ivBytes);
            IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);

            cipherTransform = "AES/" + cipherMode + "/PKCS5Padding";    
            encryptionCipher = Cipher.getInstance(cipherTransform);
            encryptionCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        }
    }


    public String encrypt(String message) throws Exception {
        byte[] messageInBytes = message.getBytes();
        byte[] encryptedBytes = encryptionCipher.doFinal(messageInBytes);
        try {
            String encryptedString = Base64.getEncoder().encodeToString(encryptedBytes);
            return encryptedString;
        } catch (IllegalArgumentException e) {
            throw new Exception("Error encoding to Base64: " + e.getMessage());
        }
    }

    public void toFile(String encryptedMessage, String keyString) throws IOException {
        File file = new File("file.txt");
        FileWriter writer = new FileWriter(file);
        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());
        writer.write("//Secret key : " + keyString + "\n" + "//Encrypted message : ");
        writer.write(encryptedMessage );
        byte[] iv = encryptionCipher.getIV();
        String encodedIV = Base64.getEncoder().encodeToString(iv);
        writer.write("\n" + "//IV : " + encodedIV + "\n");
        writer.close();
    }


    public static void main(String[] args) throws Exception {
        try {
            Scanner scanner = new Scanner(System.in);

            String input = null;
            while (input == null || input.isEmpty()) {
                System.out.println("Enter text you want to encrypt/decrypt: ");
                input = scanner.nextLine().trim(); // Text
            }

            String keyString = null;
            while (keyString == null || keyString.length() != 16) {
                System.out.println("Enter the secret key (must be 16 characters):");
                keyString = scanner.nextLine().trim(); // Secret key
            }

            System.out.println("Do you want to encrypt/decrypt text from the app or from the file ? ( 1 or 2)");

            int choice = scanner.nextInt();

            if (choice == 1) {
                String answ = "";
                String cipherMode = null;
                while (cipherMode == null) {
                    System.out.println("Enter the cipher mode (must be one of CBC, OFB, CFB, ECB):");
                    String cipherModeInput = scanner.nextLine().trim().toUpperCase();
                    if (Arrays.asList("CBC", "OFB", "CFB", "ECB").contains(cipherModeInput)) {
                        cipherMode = cipherModeInput; // Mode
                        EncryptionCBC encryption = new EncryptionCBC();
                        encryption.init(keyString, cipherMode);
                        String encryptedMessage = encryption.encrypt(input);
                        System.out.println("Do you want to save the data to the file ? (yes/no)");
                        answ = scanner.nextLine();
                        if (answ.equals("yes")) {
                            encryption.toFile(encryptedMessage, keyString);
                            System.out.println("Encrypted message: " + encryptedMessage);
                        } else {

                        }

                    }
                }
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}