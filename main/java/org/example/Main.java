package org.example;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.InputMismatchException;
import java.util.Scanner;

public class Main {
    static final String algorithm = "AES";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        menu(scanner);
        scanner.close();
    }

    public static void menu(Scanner scanner) {
        int choice = 0;
        String filePath;

        do {
            System.out.println("\nChoose an option by number: ");
            System.out.println("1. Encrypt a file");
            System.out.println("2. Decrypt a file");
            System.out.println("3. Exit");
            try {
                choice = scanner.nextInt();
                scanner.nextLine();

                if (choice == 1) {
                    System.out.println("\nEnter file path/name to encrypt: ");
                    filePath = scanner.nextLine();
                    encrypt(filePath);
                } else if (choice == 2) {
                    System.out.println("\nEnter file path/name to decrypt: ");
                    filePath = scanner.nextLine();
                    decrypt(filePath);
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
            File f = new File(filePath);
            Scanner fileReader = new Scanner(f);

            // generate random AES key
            KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            keyGen.init(128, new SecureRandom());
            SecretKey secretKey = keyGen.generateKey();
            System.out.println(secretKey);

            // reference: https://www.baeldung.com/java-aes-encryption-decryption#:~:text=We%20can%20do%20the%20AES,in%20the%20string%20input%20section.
            Cipher cipher = Cipher.getInstance(algorithm);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] fileContent;
            try (FileInputStream inputStream = new FileInputStream(filePath)) {
                fileContent = inputStream.readAllBytes();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }


        } catch (FileNotFoundException e) {
            System.out.println("Error: file not found.");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            System.out.println("Error: AES algorithm not available in your environment.");
        } catch (InvalidKeyException e) {
            System.out.println("Error: Invalid encryption key.");
        }
    }

    public static void decrypt(String filePath) {
        try {
            File f = new File(filePath);
            Scanner fileReader = new Scanner(f);

            System.out.println();
            while(fileReader.hasNext()) {
                System.out.println(fileReader.nextLine());
            }
        } catch (FileNotFoundException e) {
            System.out.println("Error: file not found.");
        }
    }
}