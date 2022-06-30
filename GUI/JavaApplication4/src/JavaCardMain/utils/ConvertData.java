/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package JavaCardMain.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.time.format.DateTimeParseException;
import java.util.Base64;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 *
 * @author Spark_Mac
 */
public class ConvertData {

    public static byte[] stringToByteArray(String string) {
        char[] chars = string.toCharArray();
        return charArrayToByteArray(chars);
    }

    public static byte[] charArrayToByteArray(char[] chars) {
        int len = chars.length;
        byte[] bytes = new byte[len];
        for (int ipIndx = 0; ipIndx < chars.length; ipIndx++) {
            bytes[ipIndx] = (byte) (chars[ipIndx] & 0x0F);
        }
        return bytes;
    }

    public static boolean isByteArrayAllZero(byte[] array) {
        for (byte b : array) {
            if (b != 0) {
                return false;
            }
        }
        return true;
    }

    public static String generateString() {
        // create a string of all characters
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        // create random string builder
        StringBuilder sb = new StringBuilder();

        // create an object of Random class
        Random random = new Random();

        // specify length of random string
        int length = 7;

        for (int i = 0; i < length; i++) {

            // generate random index number
            int index = random.nextInt(alphabet.length());

            // get character specified by index
            // from the string
            char randomChar = alphabet.charAt(index);

            // append the character to string builder
            sb.append(randomChar);
        }
        return sb.toString();
    }

    public static boolean validateDate(String input) {
        try {
            DateTimeFormatter f = new DateTimeFormatterBuilder().parseCaseInsensitive()
                    .append(DateTimeFormatter.ofPattern("dd/MM/yyyy")).toFormatter();
            LocalDate datetime = LocalDate.parse(input, f);
            if (!datetime.format(f).equals(input)) {
                System.out.println("Định dạng không hợp lệ");
                return false;
            } else {
                System.out.println(datetime.format(f));//Kết quả
                return true;
            }
        } catch (DateTimeParseException e) {
            System.out.println("Định dạng không hợp lệ");
            return false;
        }
    }

    public static void writeToFile(String path, byte[] key) throws IOException {
        System.out.println(path);
        File f = new File(path);
        f.getParentFile().mkdirs();
        FileOutputStream fos = new FileOutputStream(f);
        fos.write(key);
        fos.flush();
        fos.close();
    }

    public static void ReadfromFile(String path) throws IOException {
        File f = new File(path);
        f.getParentFile().mkdirs();
        FileInputStream fin = new FileInputStream(f);
        int i = 0;
        while ((i = fin.read()) != -1) {
            System.out.print((char) i);
        }
        fin.close();
    }
    
    public static byte[] encodeDataAes (String data, byte[] key) throws InvalidKeyException, IllegalBlockSizeException {
        try {
            SecretKeySpec secretKey = new  SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] dataEncode = cipher.doFinal(data.getBytes());
            return dataEncode;
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ConvertData.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(ConvertData.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(ConvertData.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    } 
    
    public static String DecodeDataAes (String data, byte[] key) throws InvalidKeyException, IllegalBlockSizeException {
        try {
            SecretKeySpec secretKey = new  SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] dataEncode = cipher.doFinal(Base64.getDecoder().decode(data));
            return new String(dataEncode);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ConvertData.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(ConvertData.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(ConvertData.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    } 

//    public static byte[] encrypt(String data, String publicKey) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException {
//        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//        cipher.init(Cipher.ENCRYPT_MODE, getPublicKey(publicKey));
//        return cipher.doFinal(data.getBytes());
//    }
}
