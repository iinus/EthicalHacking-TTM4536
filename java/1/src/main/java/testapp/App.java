package testapp;

public class App 
{
    public static void main(String[] args){

    }
/*
    private String[] keys(byte[] key){
        String[] keys = new String[10];
        try {
            for (int var2 = 0; var2 < 10; ++var2) {
                String keyHex = fc.toHex(key);
                keys[var2] = keyHex;

                key = fc.hash(key);
            }

        }catch ( Exception e){
            System.out.println(e.getMessage());
        }

        return keys;
    }


    private boolean check(String key){
        String encrypted = "6fe1ad578ca4fcd3fcb68e241d0dab57cded9922190ed6e91af19c564541d93d119d35580e5aa28841f00c8b5825cbcb65120da301e6826703941e12dcd68c11";
        byte[] encryptedBytes = fc.toByteFromHex(encrypted);
        encryptedBytes = fc.decrypt2(encryptedBytes, fc.toByteFromHex(key));
        String decryptedHex = fc.toHex(encryptedBytes);
        if (decryptedHex.contains(hexFlag)){
            byte[] hexBytes = fc.toByteFromHex(decryptedHex);

            String hexString = new String(hexBytes);

            System.out.println("decryptedHex: " + decryptedHex + " " + hexString);
            return true;
        }

        return false;
    }

    public void findFlag() throws Exception {
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

        String[] keys = new String[15];
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
                                    try {
                                        byte[] newByte = new byte[]{byte1, byte2, byte3, byte4, byte5, byte6, byte7, byte8, byte9, byte10, byte11, byte12, byte13, byte14, byte15, byte16};
                                        key = newByte;
                                    }catch (Exception e) {
                                        System.out.println(tag, e.getMessage());
                                    }
                                    String keyHex = fc.toHex(key);
                                    boolean foundKey = check(keyHex);

                                    if (foundKey) {
                                        System.out.println( "fant nøkkelen!! " + keys[0]);
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }

      
    }
     */ 
}

