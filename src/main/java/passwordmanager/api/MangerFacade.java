package passwordmanager.api;


import passwordmanager.api.AES.*;
import passwordmanager.api.SHA2.SHA2;

import java.security.SecureRandom;
import java.util.Arrays;

public class MangerFacade {
    public static void main(String[] args) {
        run_AES_Test();
    }

    private static void run_SHA_test(){
        SHA2 sha = new SHA2();
        sha.insert("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu".getBytes());
        System.out.println(bytesToHexString(sha.generate()));
    }

    private static String bytesToHexString(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }


    private static void run_AES_Test(){
        SecureRandom r = new SecureRandom();
        AES crypt = new AES(AES_SIZE.AES_256, AES_MODE.CTR);



        int[] key = new int[]{
                0x00010203,
                0x04050607,
                0x08090a0b,
                0x0c0d0e0f,
                0x10111213,
                0x14151617,
                0x18191a1b,
                0x1c1d1e1f
        };

        byte[] plaintext = new byte[]{
                (byte) 0x00, (byte) 0x11, (byte) 0x22, (byte) 0x33,
                (byte) 0x44, (byte) 0x55, (byte) 0x66, (byte) 0x77,
                (byte) 0x88, (byte) 0x99, (byte) 0xaa, (byte) 0xbb,
                (byte) 0xcc, (byte) 0xdd, (byte) 0xee, (byte) 0xff
        };

        String str_cleartext = "Hello my darling AES! <3. It's so wonderful to see you working as intended!";
        String str_cleartext_two = "It even works if I encrypt multiple times in a row!";

        byte[] ciphertext = crypt.encrypt(str_cleartext, key);
        byte[] ciphertext_two = crypt.encrypt(str_cleartext_two, key);

        byte[] decrypted = crypt.decrypt(ciphertext, key);

        System.out.println(new String(decrypted));
        System.out.println(new String(crypt.decrypt(ciphertext_two, key)));

    }
}