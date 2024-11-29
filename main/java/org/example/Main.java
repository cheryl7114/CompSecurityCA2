package org.example;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.InputMismatchException;
import java.util.Scanner;

public class Main {
    static final String algorithm = "AES";
    static final String cipherOutputFile = "/Users/cherylkong/Desktop/CompSecurityCA2/src/main/java/org/example/ciphertext.txt";
    static final String plainOutputFile = "/Users/cherylkong/Desktop/CompSecurityCA2/src/main/java/org/example/plaintext.txt";

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
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            keyGen.init(128, new SecureRandom());
            SecretKey secretKey = keyGen.generateKey();

            // reference: https://www.baeldung.com/java-aes-encryption-decryption#:~:text=We%20can%20do%20the%20AES,in%20the%20string%20input%20section.
            // initialize the cipher in ENCRYPT_MODE with the generated key
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

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

            System.out.println("Encrypted successfully to ciphertext.txt!");
            String encodedKey = Base64.getEncoder().encodeToString(secretKey.getEncoded());
            System.out.println("Encryption Key (keep this safe to decrypt the file): " + encodedKey);

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

            System.out.println("Decrypted successfully to plaintext.txt!");
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
}