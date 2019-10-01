package testapp;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Random;
import java.util.UUID;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import static javax.crypto.Cipher.DECRYPT_MODE;

class FlagChecker {

    static String hexFlag = toHex("ttm4536{".getBytes());

    public FlagChecker() {
        
    }
    public static void main(String[] args){
        FlagChecker fc = new FlagChecker();

        byte[] test_key = new byte[]{(byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0};
        byte[] encrypted = new byte[100];
        System.out.println("starting to find flag");
        try {
            encrypted = encrypt("ttm4536{".getBytes(),  test_key);

        } catch (Exception e){ System.out.println(e.getMessage());}
        
        byte[] decrypted = decrypt2(encrypted,test_key );
        String decryptedHex = toHex(decrypted);
        System.out.println(decryptedHex);
        try {
            findFlag();
        }
        catch (Exception e){
            System.out.println(e.getMessage());
        }
        
     
    }

    private static boolean check(String key){
        String encrypted = "6fe1ad578ca4fcd3fcb68e241d0dab57cded9922190ed6e91af19c564541d93d119d35580e5aa28841f00c8b5825cbcb65120da301e6826703941e12dcd68c11";
        byte[] encryptedBytes = toByteFromHex(encrypted);
        encryptedBytes = decrypt2(encryptedBytes, toByteFromHex(key));
        String decryptedHex = toHex(encryptedBytes);
        if (decryptedHex.contains(hexFlag)){
            byte[] hexBytes = toByteFromHex(decryptedHex);

            String hexString = new String(hexBytes);

            System.out.println("decryptedHex: " + decryptedHex + " " + hexString);
            return true;
        }

        return false;
    }

    public static boolean checkFlag(String keyStr, String flagStr) throws Exception {
        byte[] currKey = keyStr.getBytes();
        byte[] currPt = flagStr.getBytes();
        if (toHex(currPt).equals("6fe1ad578ca4fcd3fcb68e241d0dab57cded9922190ed6e91af19c564541d93d119d35580e5aa28841f00c8b5825cbcb65120da301e6826703941e12dcd68c11")) {
            return true;
        }
        return false;
    }


    public static String toHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(b & 255);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static byte[] decrypt2(byte[] input, byte[] key) {
        ByteArrayOutputStream byteOut = new ByteArrayOutputStream();
        byte[] iv = new byte[]{(byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0, (byte)0};
        try {
            IvParameterSpec IV = new IvParameterSpec(iv);
            Key skey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            cipher.init(DECRYPT_MODE, skey, IV);

            CipherOutputStream cipherOut = new CipherOutputStream(byteOut, cipher);
            cipherOut.write(input);
            cipherOut.flush();
            cipherOut.close();
        } catch (Exception e) {
            System.out.println(e.toString());
        }
        return byteOut.toByteArray();
    }

    public static byte[] encrypt(byte[] in, byte[] key) throws Exception {
        if ( key.length == 16) {
            String iv = "00000000000000000000000000000000";
            IvParameterSpec IV = new IvParameterSpec(iv.getBytes("UTF-8"));
            Key aesKey = new SecretKeySpec(key, "AES");
            Cipher encryptCipher = Cipher.getInstance("AES/CBC/NoPadding");
            encryptCipher.init(1, aesKey);
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, encryptCipher);
            cipherOutputStream.write(in);
            cipherOutputStream.flush();
            cipherOutputStream.close();
            return outputStream.toByteArray();
        }
        throw new AssertionError();
    }

    public static byte[] toByteFromHex(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }


   public static void findFlag() throws Exception {
        // 1111010010000100
        // [0, 1, 2, 3, 5, 8, 13]
        byte byte4 = (byte) 0;
        byte byte6 = (byte) 0;
        byte byte7 = (byte) 0;
        byte byte9 = (byte) 0;
        byte byte10 = (byte) 0;
        byte byte11 = (byte) 0;
        byte byte12 = (byte) 0;
        byte byte14 = (byte) 0;
        byte byte15 = (byte) 0;
        byte byte16 = (byte) 0;

        //String[] keys = new String[15];
            for (int i = 0; i < 256; i++) {
                System.out.println("status: i=" + Integer.toString(i));
                byte byte1 = (byte) i;
                for (int j = 0; j < 256; j++) {
                    byte byte2 = (byte) j;
                    for (int k = 0; k < 256; k++) {
                        byte byte3 = (byte) k;
                        for (int l = 0; l < 256; l++) {
                            byte byte5 = (byte) l;
                            for (int m = 0; m < 256; m++) {
                                byte byte8 = (byte) m;
                                for (int n = 0; n < 256; n++) {
                                    byte byte13 = (byte) n;
                                    byte[] key = new byte[]{byte1, byte2, byte3, byte4, byte5, byte6, byte7, byte8, byte9, byte10, byte11, byte12, byte13, byte14, byte15, byte16};
                                    /*
                                    try {
                                        byte[] newByte = new byte[]{byte1, byte2, byte3, byte4, byte5, byte6, byte7, byte8, byte9, byte10, byte11, byte12, byte13, byte14, byte15, byte16};
                                        key = newByte;
                                    }catch (Exception e) {
                                        System.out.println(e.getMessage());
                                    }
                                    */
                                    String keyHex = toHex(key);
                                    boolean foundKey = check(keyHex);

                                    if (foundKey) {
                                        System.out.println( "fant key!! " + keyHex);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

        
    }
}