package Lab2;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
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

public class login {
    public static void main(String[] args) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        if (args.length != 2){
            System.out.println("Usage: <database> <username>");
            System.exit(-1);
        }
        String database = args[0];
        String user = args[1];
        int cnt = 0;
        try {
            FileReader fileReader = new FileReader(new File(database));
            int newPasswordNeeded;
            do {
                Console console = System.console();

                if (console == null) {
                    System.out.println("Console not available. Exiting.");
                    System.exit(1);
                }
                char[] passwordArray = console.readPassword("Password: ");
                String password = new String(passwordArray);

                newPasswordNeeded = isPasswordChangeAndLogin(user, database, password);
                if (newPasswordNeeded == 1) {
                    changePassword(database, user, password);
                }
                cnt++;
                Thread.sleep(1000);
            }while(newPasswordNeeded==2 && cnt<3);
            if(newPasswordNeeded==2){
                System.exit(-1);
            }
            String command = "echo Proces pokrenut.";

            String osName = System.getProperty("os.name");
            if (osName.startsWith("Windows")) {
                command = "cmd.exe /c " + command;
            }

            ProcessBuilder processBuilder = new ProcessBuilder(command.split("\\s+"));

            Process process = processBuilder.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                System.out.println(line);
            }

            int exitCode = process.waitFor();
        }catch(FileNotFoundException e){
            System.out.println("Database does not exist!");
            System.exit(-1);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    static int isPasswordChangeAndLogin(String user, String database, String pass) throws FileNotFoundException {
        FileReader fileReader = new FileReader(database);
        try (BufferedReader reader = new BufferedReader(fileReader)) {
            String line;
            boolean userfound = false;
            while ((line = reader.readLine()) != null) {
                String[] parts = line.split(" ");
                if (parts.length != 3) {
                    System.out.println("Integrity compromised");
                    System.exit(-1);
                }
                String userRead = parts[0];
                if (userRead.equals(user)) {
                    reader.close();
                    userfound = true;
                    if(!checkIfSamePassword(pass,parts[1])){
                        reader.close();
                        System.out.println("Wrong username or password.");
                        return 2;
                    }
                    if (parts[2].equals("true")){
                        reader.close();
                        return 1;
                    }
                }
            }
            reader.close();
            if(userfound)
                return 0;
            fakeLogin();
        } catch (IOException | InvalidKeySpecException | NoSuchAlgorithmException | InterruptedException e) {
            throw new RuntimeException(e);
        }
        return 0;
    }
    static void fakeLogin() throws InterruptedException {
        int counter = 0;
        do{
            Console console = System.console();

            if (console == null) {
                System.out.println("Console not available. Exiting.");
                System.exit(1);
            }
            char[] passwordArray = console.readPassword("Password: ");
            counter++;
            Thread.sleep(1000);
        }while(counter<2);
    }
    static void changePassword(String database,String user, String pass) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        String newPass ;
        while (true){
            newPass = newPassword();
            if (newPass.equals(pass)){
                System.out.println("New password can't be the same as old password!");
                continue;
            }
            break;
        }
        addUser(database,user,newPass);
    }
    static String newPassword(){
        Console console = System.console();

        if (console == null) {
            System.out.println("Console not available. Exiting.");
            System.exit(1);
        }
        char[] passwordArray = console.readPassword("New password: ");
        String password = new String(passwordArray);
        passwordArray = console.readPassword("Repeat new password: ");
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
    static void addUser(String database,String user,String password) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
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
                } else {
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
            BufferedWriter writer = new BufferedWriter(new FileWriter(file, true));
            writer.append(user).append(" ").append(passwordHash(password)).append(" ").append("false");
            writer.close();
            System.out.println("Password changed.");
        }
    }
    static boolean checkIfSamePassword(String newPassword, String hashOldPassword) throws InvalidKeySpecException, NoSuchAlgorithmException {
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
        return passwordsMatch;
    }
}
