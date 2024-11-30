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
        String filePath, secretKey;

        do {
            System.out.println("\nChoose an option by number: ");
            System.out.println("1. Encrypt a file");
            System.out.println("2. Decrypt a file");
            System.out.println("3. Exit");
            try {
                choice = scanner.nextInt();
                scanner.nextLine();

                if (choice == 1) {
                    System.out.print("\nEnter file path/name to encrypt: ");
                    filePath = scanner.next();
                    encrypt(filePath);
                } else if (choice == 2) {
                    System.out.print("\nEnter file path/name to decrypt: ");
                    filePath = scanner.next();
                    System.out.print("Enter the Base64-encoded key: ");
                    secretKey = scanner.next();
                    decrypt(filePath, secretKey);
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

    public static void encrypt(String filePath) {
        try {
            // generate random AES key
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128, new SecureRandom());
            SecretKey secretKey = keyGen.generateKey();

            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            // reference: https://www.baeldung.com/java-aes-encryption-decryption#:~:text=We%20can%20do%20the%20AES,in%20the%20string%20input%20section.
            // initialize the cipher in ENCRYPT_MODE with the generated key
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);

            // used to read contents of the file
            FileInputStream inputStream = new FileInputStream(filePath);
            // used to write encrypted data to the output file
            FileOutputStream outputStream = new FileOutputStream(cipherOutputFile);

            // read the input file in chunks of 64 bytes
            byte[] buffer = new byte[64];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                // encrypt the data in chunks
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    // write the encrypted chunks (if not null) to the output file.
                    outputStream.write(output);
                }
            }

            // handle any remaining data and add necessary padding
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                // write the final encrypted block to the output file
                outputStream.write(outputBytes);
            }
            inputStream.close();
            outputStream.close();

            System.out.println("Encrypted successfully! The cipher is written to ciphertext.txt - please check your file directory.");
            // source: https://medium.com/@AlexanderObregon/javas-base64-getencoder-method-explained-d3c331139837
            String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
            String encodedIV = Base64.getEncoder().encodeToString(iv);
            saveKeyAndIV(encodedKey,encodedIV);
            System.out.println("The key and IV parameter used in this process are saved to keys.txt. Please make sure you have the correct combination for decryption.");
        } catch (FileNotFoundException e) {
            System.out.println("Error: File not found.");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.out.println("Error: AES algorithm not available in your environment.");
        } catch (InvalidKeyException e) {
            System.out.println("Error: Invalid encryption key.");
        } catch (IllegalBlockSizeException e) {
            System.out.println("Error: Data size is incompatible with the encryption algorithm.");
        } catch (IOException e) {
            System.out.println("Error: File content unreadable.");
        } catch (BadPaddingException e) {
            System.out.println("Error: Invalid encryption padding.");
        } catch (InvalidAlgorithmParameterException e) {
            System.out.println("Error: Invalid IV parameter.");
        }
    }

    public static void decrypt(String filePath, String key) {
        try {
            // Decode the Base64-encoded key
            byte[] decodedKey = Base64.getDecoder().decode(key);
            SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            // used to read contents of the file
            FileInputStream inputStream = new FileInputStream(filePath);
            // used to write encrypted data to the output file
            FileOutputStream outputStream = new FileOutputStream(plainOutputFile);

            // read the input file in chunks of 64 bytes
            byte[] buffer = new byte[64];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                // encrypt the data in chunks
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    // write the encrypted chunks (if not null) to the output file.
                    outputStream.write(output);
                }
            }

            // handle any remaining data and add necessary padding
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                // write the final encrypted block to the output file
                outputStream.write(outputBytes);
            }
            inputStream.close();
            outputStream.close();

            System.out.println("Encrypted successfully! The cipher is written to plaintext.txt - please check your file directory.");
        } catch (FileNotFoundException e) {
            System.out.println("Error: File not found.");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.out.println("Error: AES algorithm not available in your environment.");
        } catch (InvalidKeyException e) {
            System.out.println("Error: Invalid encryption key.");
        } catch (IllegalBlockSizeException e) {
            System.out.println("Error: Data size is incompatible with the encryption algorithm.");
        } catch (IOException e) {
            System.out.println("Error: File content unreadable.");
        } catch (BadPaddingException e) {
            System.out.println("Error: Invalid encryption padding.");
        }
    }

    public static void saveKeyAndIV(String key, String iv) {
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
}