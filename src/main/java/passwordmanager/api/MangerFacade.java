package passwordmanager.api;



public class MangerFacade {
    public static void main(String[] args) {
        AES crypt = new AES(AES.AES_VARIANT.AES_256);

        int[] key = new int[]{
                0x603deb10, 0x15ca71be, 0x2b73aef0, 0x857d7781,
                0x1f352c07, 0x3b6108d7, 0x2d9810a3, 0x0914dff4
        };

        byte[] plaintext = new byte[]{
               1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, -1
        };

        String str_cleartext = "Hello AES!";

        byte[] ciphertext = crypt.encrypt(str_cleartext.getBytes(), key);
        String decrypted = new String(crypt.decrypt(ciphertext, key));


        System.out.println(decrypted);

    }
}