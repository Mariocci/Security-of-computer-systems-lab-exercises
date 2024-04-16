package Lab2;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class usermgmt {
    static String path;
    public static void main(String[] args) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        String command = args[0];
        switch (command) {
            case "add":
                addUser(args[1], args[2]);
                break;
            case "passwd":
                changePassword(args[1], args[2]);
                break;
            case "forcepass":
                forcePassword(args[1], args[2]);
                break;
            case "del":
                delete(args[1], args[2]);
                break;
            case "init":
                path = args[1];
                initDb();
                System.out.println("Database initialized with name " + args[1] + ".");
                break;
            default:
                System.out.println("Unknown command: " + command);
                break;
        }
    }
    static void addUser(String database,String user) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        String password = loginProcess();
        File file = new File(database);
        if(!file.exists()) {
            System.out.println("Database does not exist!");
            System.exit(-1);
        }
        BufferedWriter writer = new BufferedWriter(new FileWriter(file, true));
        writer.append(user).append(" ").append(passwordHash(password)).append(" ").append("false");
        writer.close();
        System.out.println("User " + user + " added.");
    }
    static void changePassword(String database,String user){
        File file = new File(database);
        if(!file.exists()) {
            System.out.println("Database does not exist!");
            System.exit(-1);
        }
        String password = loginProcess();
        List<String> updatedLines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(" ");
                if (parts.length != 3) {
                    System.out.println("Integrity compromised");
                    System.exit(-1);
                }
                String userRead = parts[0];
                if (userRead.equals(user)) {
                    checkIfSamePassword(password, parts[1]);
                    updatedLines.add(user + " " + passwordHash(password) + " false");
                }
                else {
                    updatedLines.add(line);
                }
            }
            try (FileWriter writer = new FileWriter(file)) {
                for (String updatedLine : updatedLines) {
                    writer.write(updatedLine + "\n");
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        System.out.println("Password for user " + user + " changed.");
    }
    static void forcePassword(String database,String user){
        File file = new File(database);
        if(!file.exists()) {
            System.out.println("Database does not exist!");
            System.exit(-1);
        }
        List<String> updatedLines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(" ");
                if (parts.length != 3) {
                    System.out.println("Integrity compromised");
                    System.exit(-1);
                }
                String userRead = parts[0];
                if (userRead.equals(user)) {
                    updatedLines.add(user + " " + parts[1] + " true");
                }
                else {
                    updatedLines.add(line);
                }
            }
            try (FileWriter writer = new FileWriter(file)) {
                for (String updatedLine : updatedLines) {
                    writer.write(updatedLine + "\n");
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        System.out.println("User " + user + " will be requested to change password on next login.");
    }
    static void delete(String database,String user){
        File file = new File(database);
        if(!file.exists()) {
            System.out.println("Database does not exist!");
            System.exit(-1);
        }
        List<String> updatedLines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(" ");
                if (parts.length != 3) {
                    System.out.println("Integrity compromised");
                    System.exit(-1);
                }
                String userRead = parts[0];
                if (userRead.equals(user)) {
                   continue;
                }
                else {
                    updatedLines.add(line);
                }
            }
            try (FileWriter writer = new FileWriter(file)) {
                for (String updatedLine : updatedLines) {
                    writer.write(updatedLine + "\n");
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        System.out.println("User " + user + " deleted.");
    }
    public static String passwordHash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int iterations = 3000;
        int saltLength = 16;
        int desiredKeyLength = 256;

        SecureRandom secureRandom = new SecureRandom();
        byte[] salt = new byte[saltLength];
        secureRandom.nextBytes(salt);

        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterations, desiredKeyLength);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] hash = secretKeyFactory.generateSecret(spec).getEncoded();

        byte[] combined = new byte[hash.length + salt.length];
        System.arraycopy(hash, 0, combined, 0, hash.length);
        System.arraycopy(salt, 0, combined, hash.length, salt.length);

        return Base64.getEncoder().encodeToString(combined);
    }
    static void initDb() throws IOException {
        File file = new File(path);
        if (file.exists()) {
            file.delete();
        }
        Files.createFile(file.toPath());
    }
    static String loginProcess(){
        Console console = System.console();

        if (console == null) {
            System.out.println("Console not available. Exiting.");
            System.exit(1);
        }
        char[] passwordArray = console.readPassword("Password: ");
        String password = new String(passwordArray);
        passwordArray = console.readPassword("Repeat password: ");
        String passwordRepeat = new String(passwordArray);
        if (!password.equals(passwordRepeat)){
            System.out.println("User add or password change failed. Password mismatch.");
            System.exit(1);
        }
        String regex = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[.,!@#$%^&*()-+=])[A-Za-z\\d.,!@#$%^&*()-+=]{10,}$";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(password);
        if(!matcher.matches()){
            System.out.println("Password needs to be at least 10 characters long and contain at least one uppercase letter, lowercase letter, number and special character [.,!@#$%^&*()-+=].");
            System.exit(1);
        }
        return password;
    }
    static void checkIfSamePassword(String newPassword, String hashOldPassword) throws InvalidKeySpecException, NoSuchAlgorithmException {
        byte[] oldPasswordHashBytes = Base64.getDecoder().decode(hashOldPassword);
        byte[] salt = new byte[16];

        System.arraycopy(oldPasswordHashBytes, oldPasswordHashBytes.length - 16, salt, 0, 16);

        PBEKeySpec spec = new PBEKeySpec(newPassword.toCharArray(), salt, 3000, 256);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] newHash = secretKeyFactory.generateSecret(spec).getEncoded();

        boolean passwordsMatch = MessageDigest.isEqual(
                Arrays.copyOfRange(oldPasswordHashBytes, 0, oldPasswordHashBytes.length - 16),
                newHash
        );
        if (passwordsMatch) {
            System.out.println("New password can't be the same as the old password.");
            System.exit(1);
        }
    }
}

