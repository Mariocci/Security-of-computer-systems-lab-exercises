import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class tajnik {
    static byte[] salt;

    public static void main(String[] args) throws Exception {
        String command = args[0];
        switch (command) {
            case "init":
                if (args.length < 2) {
                    System.out.println("Usage: java tajnik init <fileName>");
                    return;
                }
                String fileName = args[1];
                try {
                    System.out.println("Password DB initialized with name : " + initDB(fileName));
                } catch (IOException e) {
                    System.out.println("Error : " + e.getMessage());
                }
                break;
            case "put":
                if (args.length < 5) {
                    System.out.println("Format: java tajnik put <fileName> <masterPassword> <address> <password>");
                    return;
                }
                String fileNamePut = args[1];
                String masterPasswordPut = args[2];
                String address = args[3];
                String password = args[4];
                System.out.println("Stored password for " + address + ": " + storePassword(address, masterPasswordPut, password, fileNamePut));
                break;
            case "get":
                if (args.length < 4) {
                    System.out.println("Usage: java tajnik get <fileName> <masterPassword> <address>");
                    return;
                }
                String fileNameGet = args[1];
                String masterPasswordGet = args[2];
                String addressGet = args[3];
                System.out.println("Password for " + addressGet + " is: " + getPassword(addressGet, masterPasswordGet, fileNameGet));
                break;
            default:
                System.out.println("Unknown command: " + command);
                break;
        }
    }
    static String storePassword(String address, String masterPassword, String password, String fileName) throws Exception {
        File file = new File(fileName);
        if(!file.exists()) {
            System.out.println("Database does not exist!");
            System.exit(-1);
        }
        BufferedReader br = new BufferedReader(new FileReader(file));
        if(file.length()>0){
            String  firstLine= br.readLine();
            SecretKey key = getKey(masterPassword, firstLine);
            List<String> parts = Arrays.stream(decode(firstLine, key).split("\\|")).toList();
            try {
                if (!parts.isEmpty()) {
                    String hashed = hash(parts.get(0) + '|' + parts.get(1));
                    if (!hashed.equals(parts.get(2))) {
                        System.out.println("Wrong password or integrity compromised");
                        System.exit(-1);
                    }
                }
            }
            catch(Exception e){
                System.out.println("Wrong password or integrity compromised");
                System.exit(-1);
            }
        }
        findByAddressAndRemove(masterPassword,address,file);
        BufferedWriter writer = new BufferedWriter(new FileWriter(file, true));
        writer.append(encode(address,password,masterPassword,hash(address+'|'+password)));
        writer.close();
        return password;
    }
    static String getPassword(String address, String masterPassword, String fileNameGet) throws Exception {
        File file = new File(fileNameGet);
        BufferedReader br = new BufferedReader(new FileReader(file));
        String  firstLine= br.readLine();
        SecretKey key = getKey(masterPassword,firstLine);
        List<String> parts = Arrays.stream(decode(firstLine,key).split("\\|")).toList();

        try {
            if (!parts.isEmpty()) {
                String hashed = hash(parts.get(0) + '|' + parts.get(1));
                if (!hashed.equals(parts.get(2))) {
                    System.out.println("Wrong password or integrity compromised");
                    System.exit(-1);
                }
            }
        }
        catch(Exception e){
            System.out.println("Wrong password or integrity compromised");
            System.exit(-1);
        }

        List<String> list = findByAddress(masterPassword,address,new File(fileNameGet));
        if (list.size() > 1) {
            System.out.println("Wrong password or integrity compromised");
            System.exit(-1);
        } else if (list.isEmpty()) {
            System.out.println("Address not found!");
            System.exit(-1);
        }

        String[] partsStr = list.get(0).split("\\|");
        String storedAddress = partsStr[0];
        String storedRawPassword = partsStr[1];
        String storedHash = partsStr[2];

        String hashFromData = hash(storedAddress + "|" + storedRawPassword);

        if (!storedHash.equals(hashFromData)) {
            System.out.println("Incorrect password or integrity compromised!");
            System.exit(-1);
        }
        return storedRawPassword;
    }
    static List<String> findByAddressAndRemove(String masterPassword, String address, File file) throws Exception {
        List<String> matchingLines = new ArrayList<>();
        List<String> updatedLines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            int cnt=1;
            while ((line = reader.readLine()) != null) {
                SecretKey key=getKey(masterPassword,line);

                String decodedLine = decode(line, key);

                String[] parts = decodedLine.split("\\|");
                if (parts.length != 3) {
                    System.out.println("Wrong password or integrity compromised");
                    System.exit(-1);
                }

                String decodedAddress = parts[0];
                if (decodedAddress.equals(address)) {
                    matchingLines.add(decodedLine);
                }
                else {
                    updatedLines.add(line);
                }
                cnt++;
            }
            try (FileWriter writer = new FileWriter(file)) {
                for (String updatedLine : updatedLines) {
                    writer.write(updatedLine + "\n");
                }
                writer.close();
            }

        }
        return matchingLines;
    }
    static List<String> findByAddress(String masterPassword, String address, File file) throws Exception {
        List<String> matchingLines = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            int cnt=1;
            while ((line = reader.readLine()) != null) {
                SecretKey key=getKey(masterPassword,line);

                String decodedLine = decode(line, key);

                String[] parts = decodedLine.split("\\|");
                if (parts.length != 3) {
                    System.out.println("Wrong password or integrity compromised");
                    System.exit(-1);
                }

                String decodedAddress = parts[0];
                if (decodedAddress.equals(address)) {
                    matchingLines.add(decodedLine);
                }
                cnt++;
            }
        }
        return matchingLines;
    }
    static String initDB(String fileName) throws IOException {
        File file = new File(fileName);
        if (file.exists()) {
            file.delete();
        }
        Files.createFile(file.toPath());
        return file.getName();
    }
    static SecretKey getKey(String masterPassword, String line) throws Exception {
        byte[] lineBytes = Base64.getDecoder().decode(line);
        salt = Arrays.copyOfRange(lineBytes, lineBytes.length - 28, lineBytes.length - 12);
        return deriveKeyWithSalt(masterPassword);
    }
     static String encode(String address,String password,String masterPassword,String hash) throws Exception {
        SecretKey  key = deriveKey(masterPassword);
        byte[] bytes = (address+'|'+password+'|'+hash).getBytes(StandardCharsets.UTF_8);

         byte[] iv = generateIV();
         Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
         cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));

         byte[] encryptedBytes = cipher.doFinal(bytes);

         ByteBuffer combinedBuffer = ByteBuffer.allocate( encryptedBytes.length + salt.length + iv.length );
         combinedBuffer.put(encryptedBytes);
         combinedBuffer.put(salt);
         combinedBuffer.put(iv);

         return Base64.getEncoder().encodeToString(combinedBuffer.array());
    }
     static String decode(String line, SecretKey key) throws Exception {
         try {
             byte[] encodedBytes = Base64.getDecoder().decode(line);

             int saltLength = 16;
             byte[] iv = Arrays.copyOfRange(encodedBytes, encodedBytes.length - 12, encodedBytes.length);
             byte[] encryptedBytes = Arrays.copyOfRange(encodedBytes, 0, encodedBytes.length - 12 - saltLength);

             Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
             GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(128, iv);
             cipher.init(Cipher.DECRYPT_MODE, key, gcmParameterSpec);

             byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

             return new String(decryptedBytes, StandardCharsets.UTF_8);
         } catch (Exception e) {
             System.out.println("Wrong password or integrity compromised");
             System.exit(-1);
         }
         return null;
     }


     static SecretKey deriveKey(String masterPassword) throws Exception {
        byte[] masterPasswordBytes = masterPassword.getBytes();

        SecureRandom secureRandom = new SecureRandom();
        salt = new byte[16];
        secureRandom.nextBytes(salt);

        int iterations = 10000;

        int keyLength = 256;

        char[] passwordChars = new String(masterPasswordBytes, StandardCharsets.UTF_8).toCharArray();
        KeySpec keySpec = new PBEKeySpec(passwordChars, salt, iterations, keyLength);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(keySpec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }
    static SecretKey deriveKeyWithSalt(String masterPassword) throws Exception {
        byte[] masterPasswordBytes = masterPassword.getBytes();

        int iterations = 10000;
        int keyLength = 256;

        char[] passwordChars = new String(masterPasswordBytes, StandardCharsets.UTF_8).toCharArray();
        KeySpec keySpec = new PBEKeySpec(passwordChars, salt, iterations, keyLength);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = factory.generateSecret(keySpec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }
     static String hash(String addressPassword) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");

        byte[] hashedBytes = digest.digest(addressPassword.getBytes());

        StringBuilder hexString = new StringBuilder();
        for (byte b : hashedBytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }
    static byte[] generateIV() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] iv = new byte[12];
        secureRandom.nextBytes(iv);
        return iv;
    }
}