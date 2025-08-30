package passwordmanager.crypt;


import passwordmanager.crypt.cipher.aes.AES;
import passwordmanager.crypt.cipher.aes.AES_MODE;
import passwordmanager.crypt.cipher.aes.AES_SIZE;
import passwordmanager.crypt.hash.Blake2b;
import passwordmanager.crypt.hash.HMAC;
import passwordmanager.crypt.hash.SHA2;
import passwordmanager.crypt.kdf.argon2.ARGON2_TYPE;
import passwordmanager.crypt.kdf.argon2.Argon2;
import passwordmanager.crypt.kdf.PBKDF2;
import passwordmanager.crypt.kdf.scrypt.Scrypt;
import passwordmanager.crypt.kdf.scrypt.salsa20_core;

public class TestCases {

    public static void main(String[] args) {
        run_scrypt_test();
    }


    private static void run_scrypt_test() {
        Scrypt scrypt = new Scrypt();

        byte[] test_block = new byte[] {
                (byte)0xf7, (byte)0xce, (byte)0x0b, (byte)0x65, (byte)0x3d, (byte)0x2d, (byte)0x72, (byte)0xa4,
                (byte)0x10, (byte)0x8c, (byte)0xf5, (byte)0xab, (byte)0xe9, (byte)0x12, (byte)0xff, (byte)0xdd,
                (byte)0x77, (byte)0x76, (byte)0x16, (byte)0xdb, (byte)0xbb, (byte)0x27, (byte)0xa7, (byte)0x0e,
                (byte)0x82, (byte)0x04, (byte)0xf3, (byte)0xae, (byte)0x2d, (byte)0x0f, (byte)0x6f, (byte)0xad,
                (byte)0x89, (byte)0xf6, (byte)0x8f, (byte)0x48, (byte)0x11, (byte)0xd1, (byte)0xe8, (byte)0x7b,
                (byte)0xcc, (byte)0x3b, (byte)0xd7, (byte)0x40, (byte)0x0a, (byte)0x9f, (byte)0xfd, (byte)0x29,
                (byte)0x09, (byte)0x4f, (byte)0x01, (byte)0x84, (byte)0x63, (byte)0x95, (byte)0x74, (byte)0xf3,
                (byte)0x9a, (byte)0xe5, (byte)0xa1, (byte)0x31, (byte)0x52, (byte)0x17, (byte)0xbc, (byte)0xd7,
                (byte)0x89, (byte)0x49, (byte)0x91, (byte)0x44, (byte)0x72, (byte)0x13, (byte)0xbb, (byte)0x22,
                (byte)0x6c, (byte)0x25, (byte)0xb5, (byte)0x4d, (byte)0xa8, (byte)0x63, (byte)0x70, (byte)0xfb,
                (byte)0xcd, (byte)0x98, (byte)0x43, (byte)0x80, (byte)0x37, (byte)0x46, (byte)0x66, (byte)0xbb,
                (byte)0x8f, (byte)0xfc, (byte)0xb5, (byte)0xbf, (byte)0x40, (byte)0xc2, (byte)0x54, (byte)0xb0,
                (byte)0x67, (byte)0xd2, (byte)0x7c, (byte)0x51, (byte)0xce, (byte)0x4a, (byte)0xd5, (byte)0xfe,
                (byte)0xd8, (byte)0x29, (byte)0xc9, (byte)0x0b, (byte)0x50, (byte)0x5a, (byte)0x57, (byte)0x1b,
                (byte)0x7f, (byte)0x4d, (byte)0x1c, (byte)0xad, (byte)0x6a, (byte)0x52, (byte)0x3c, (byte)0xda,
                (byte)0x77, (byte)0x0e, (byte)0x67, (byte)0xbc, (byte)0xea, (byte)0xaf, (byte)0x7e, (byte)0x89
        };

        System.out.println(bytesToHexString(scrypt.scrypt("pleaseletmein".getBytes(), "SodiumChloride".getBytes(), 20, 8, 1, 64)));
    }

    private static void run_PBKDF2_test() {
        PBKDF2 kdf = new PBKDF2();

        System.out.println(bytesToHexString(kdf.generate("Password".getBytes(), "NaCl".getBytes(), 600000, 64)));

    }

    private static void run_argon2_test() {
        Argon2 argon2 = new Argon2();

        byte[] password = new byte[32];
        byte[] salt = new byte[16];
        byte[] assocData = new byte[12];
        byte[] secret = new byte[8];

        for (int i = 0; i < password.length; i++) {
            password[i] = (byte) 0x01;
        }
        for (int i = 0; i < salt.length; i++) {
            salt[i] = (byte) 0x02;
        }
        for (int i = 0; i < secret.length; i++) {
            secret[i] = (byte) 0x03;
        }
        for (int i = 0; i < assocData.length; i++) {
            assocData[i] = (byte) 0x04;
        }

        System.out.println(bytesToHexString(argon2.argon2(password, salt, secret, assocData, 4, 32, 32, 3, 0x13, ARGON2_TYPE.ARGON2_d)));
    }

    private static void run_blake2b_test() {

        byte[] key = new byte[]{
                (byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
                (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
                (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B,
                (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F,

                (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
                (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
                (byte)0x18, (byte)0x19, (byte)0x1A, (byte)0x1B,
                (byte)0x1C, (byte)0x1D, (byte)0x1E, (byte)0x1F,

                (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
                (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
                (byte)0x28, (byte)0x29, (byte)0x2A, (byte)0x2B,
                (byte)0x2C, (byte)0x2D, (byte)0x2E, (byte)0x2F,

                (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33,
                (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
                (byte)0x38, (byte)0x39, (byte)0x3A, (byte)0x3B,
                (byte)0x3C, (byte)0x3D, (byte)0x3E, (byte)0x3F
        };

        byte[] message = new byte[]{(byte)0x00, (byte)0x01, (byte)0x02, (byte)0x03,
                (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07,
                (byte)0x08, (byte)0x09, (byte)0x0A, (byte)0x0B,
                (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F,

                (byte)0x10, (byte)0x11, (byte)0x12, (byte)0x13,
                (byte)0x14, (byte)0x15, (byte)0x16, (byte)0x17,
                (byte)0x18, (byte)0x19, (byte)0x1A, (byte)0x1B,
                (byte)0x1C, (byte)0x1D, (byte)0x1E, (byte)0x1F,

                (byte)0x20, (byte)0x21, (byte)0x22, (byte)0x23,
                (byte)0x24, (byte)0x25, (byte)0x26, (byte)0x27,
                (byte)0x28, (byte)0x29, (byte)0x2A, (byte)0x2B,
                (byte)0x2C, (byte)0x2D, (byte)0x2E, (byte)0x2F,

                (byte)0x30, (byte)0x31, (byte)0x32, (byte)0x33,
                (byte)0x34, (byte)0x35, (byte)0x36, (byte)0x37,
                (byte)0x38, (byte)0x39, (byte)0x3A, (byte)0x3B,
                (byte)0x3C, (byte)0x3D, (byte)0x3E, (byte)0x3F,

                (byte) 0x40, (byte) 0x41, (byte) 0x42, (byte) 0x43
        };

        byte[] small_message = new byte[] {
                (byte) 0x00, (byte) 0x01
        };

        byte[] zero_key = new byte[0];

        byte[] long_message = new byte[255];
        for (int i = 0; i < 255; i++) {
            long_message[i] = (byte) i;
        }

        byte[] zero_message = new byte[0];

        Blake2b blake = new Blake2b(key, 64);

        blake.insert(zero_message);

        System.out.println(bytesToHexString(Blake2b.hash(key, zero_message, 64)));
        System.out.println(bytesToHexString(blake.generate()));
    }

    private static void run_HMAC_test() {
        HMAC hmac = new HMAC(new SHA2());

        byte[] key = new byte[] {
                (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b,
                (byte)0x0b, (byte)0x0b, (byte)0x0b, (byte)0x0b
        };

        byte[] long_key = new byte[20];
        for (int i = 0; i < long_key.length; i++) {
            long_key[i] = (byte) 0xAA;
        }

        byte[] long_message = new byte[50];
        for (int i = 0; i < long_message.length; i++) {
            long_message[i] = (byte) 0xDD;
        }

        System.out.println(bytesToHexString(hmac.generate("Hi There".getBytes(), key, 64)));
        System.out.println(bytesToHexString(hmac.generate("what do ya want for nothing?".getBytes(), "Jefe".getBytes(), 64)));
        System.out.println(bytesToHexString(hmac.generate(long_message, long_key, 64)));


    }

    private static void run_SHA_test(){
        SHA2 sha = new SHA2();
        sha.insert("12345!".getBytes());
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