package org.example;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.InputMismatchException;
import java.util.Scanner;

public class Main {
    static final String algorithm = "AES/CBC/PKCS5Padding";
    static final String cipherOutputFile = "/Users/cherylkong/Desktop/CompSecurityCA2/src/main/java/org/example/ciphertext.txt";
    static final String plainOutputFile = "/Users/cherylkong/Desktop/CompSecurityCA2/src/main/java/org/example/plaintext.txt";
    static final String keysFile = "/Users/cherylkong/Desktop/CompSecurityCA2/src/main/java/org/example/keys.txt";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        menu(scanner);
        scanner.close();
    }

    public static void menu(Scanner scanner) {
        int choice = 0;
        String filePath, secretKey, iv;

        do {
            System.out.println("\nChoose an option by number: ");
            System.out.println("1. Encrypt a file");
            System.out.println("2. Decrypt a file");
            System.out.println("3. Exit");
            try {
                choice = scanner.nextInt();
                scanner.nextLine();

                if (choice == 1) {
                    filePath = getValidFilePath(scanner);
                    encrypt(filePath, scanner);
                } else if (choice == 2) {
                    // Validate file path
                    filePath = getValidFilePath(scanner);
                    // Validate secret key
                    secretKey = getValidBase64EncodedInput(scanner, "key");
                    // Validate IV
                    iv = getValidBase64EncodedInput(scanner, "IV");
                    decrypt(filePath, secretKey, iv);
                } else if (choice == 3) {
                    System.out.println("Bye!");
                } else {
                    System.out.println("\nInvalid choice. Please try again.");
                }
            } catch (InputMismatchException e) {
                System.out.println("\nInvalid input. Please enter a number.");
                scanner.nextLine();
            }
        } while (choice != 3);
    }

    // encrypt file
    private static void encrypt(String filePath, Scanner scanner) {
        try {
            // generate random AES key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128, new SecureRandom());
            SecretKey secretKey = keyGen.generateKey();

            // generate random IV
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // reference: https://www.baeldung.com/java-aes-encryption-decryption#:~:text=We%20can%20do%20the%20AES,in%20the%20string%20input%20section.
            // initialize the cipher in ENCRYPT_MODE with the generated key
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            processFile(cipher, filePath, cipherOutputFile);

            System.out.println("Encrypted successfully! The cipher is written to ciphertext.txt - please check your file directory.");

            // source: https://medium.com/@AlexanderObregon/javas-base64-getencoder-method-explained-d3c331139837
            String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
            String encodedIV = Base64.getEncoder().encodeToString(iv);
            System.out.println("Key: " + encodedKey);
            System.out.println("IV: " + encodedIV);
            while (true) {
                // ask if user wants to save the key and iv used for encryption
                System.out.print("Do you want to save the key and IV into a file? (Y/N): ");
                String answer = scanner.nextLine();
                answer = answer.substring(0,1).toUpperCase();

                if (!answer.equals("Y") && !answer.equals("N")) {
                    System.out.println("Invalid input. Try again.");
                } else {
                    if (answer.equals("Y")) {
                        saveKeyAndIV(encodedKey,encodedIV);
                        System.out.println("The key and IV used in this process are saved to keys.txt. Please make sure you have the correct combination for decryption.");
                    }
                    return;
                }
            }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.out.println("Error: Unsupported AES algorithm or padding.");
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            System.out.println("Error: Invalid key or IV.");
        }
    }

    // decrypt file
    private static void decrypt(String filePath, String key, String iv) {
        try {
            // Decode the Base64-encoded key
            byte[] decodedKey = Base64.getDecoder().decode(key);
            SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
            // Decode the Base64-encoded IV
            byte[] decodedIV = Base64.getDecoder().decode(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(decodedIV);

            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            processFile(cipher, filePath, plainOutputFile);

            System.out.println("Decrypted successfully! The decrypted content is written to plaintext.txt - please check your file directory.");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.out.println("Error: Unsupported AES algorithm or padding.");
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            System.out.println("Error: Invalid key or IV.");
        }
    }

    // process and encrypt/ decrypt file, write content to respective location
    private static void processFile(Cipher cipher, String inputFilePath, String outputFilePath) {
        try {
            // used to read contents of the file
            try (FileInputStream inputStream = new FileInputStream(inputFilePath);
                 // used to write encrypted data to the output file
                 FileOutputStream outputStream = new FileOutputStream(outputFilePath)) {

                // read the input file in chunks of 64 bytes
                byte[] buffer = new byte[64];
                int bytesRead;
                while ((bytesRead = inputStream.read(buffer)) != -1) {
                    // encrypt the data in chunks
                    byte[] output = cipher.update(buffer, 0, bytesRead);
                    if (output != null) {
                        // write the encrypted chunks (if not null) to the output file
                        outputStream.write(output);
                    }
                }
                // handle any remaining data and add necessary padding
                byte[] outputBytes = cipher.doFinal();
                if (outputBytes != null) {
                    // write the final encrypted block to the output file
                    outputStream.write(outputBytes);
                }
            }
        } catch (IOException e) {
            System.out.println("Error: Unable to read/write file.");
        } catch (IllegalBlockSizeException e) {
            System.out.println("Error: Data size is incompatible with the encryption algorithm.");
        } catch (BadPaddingException e) {
            System.out.println("Error: Invalid encryption padding.");
        }
    }

    // save key and iv into keys.txt
    private static void saveKeyAndIV(String key, String iv) {
        try (FileWriter fw = new FileWriter(keysFile, true)) {
            // source: https://www.w3schools.com/java/java_date.asp
            LocalDateTime dateTime = LocalDateTime.now();
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd-MM-yyyy HH:mm:ss");
            String formattedDate = dateTime.format(formatter);

            fw.write(formattedDate + "\n");
            fw.write("Key: " + key + "\n");
            fw.write("IV: " + iv + "\n\n");
        } catch (IOException e) {
            System.out.println("Error: Unable to write keys into file.");
        }
    }

    // file path validator
    private static String getValidFilePath(Scanner scanner) {
        String filePath;
        while (true) {
            System.out.print("Enter file path/name: ");
            filePath = scanner.nextLine().trim();
            File file = new File(filePath);
            if (file.exists() && file.canRead()) {
                return filePath;
            } else {
                System.out.println("Invalid file path or file not readable. Please try again.");
            }
        }
    }

    private static String getValidBase64EncodedInput(Scanner scanner, String inputType) {
        String input;
        while (true) {
            System.out.print("Enter the Base64-encoded " + inputType + ": ");
            input = scanner.next();

            try {
                byte[] decoded = Base64.getDecoder().decode(input);
                if (decoded.length == 16) { // AES block size is 16 bytes
                    return input;
                } else {
                    System.out.println("Invalid " + inputType + " size. Ensure it is a 128-bit Base64-encoded string.");
                }
            } catch (IllegalArgumentException e) {
                System.out.println("Invalid Base64 format. Please enter a properly Base64-encoded string.");
            }
        }
    }
}