package passwordmanager.crypt.kdf;

import passwordmanager.crypt.hash.HMAC;
import passwordmanager.crypt.hash.SHA2;

import java.security.SecureRandom;

public class PBKDF2 {


    public PBKDF2() {
        hmac = new HMAC(new SHA2());
        rand = new SecureRandom();
    }

    private final HMAC hmac;
    private final SecureRandom rand;
    private final int hLen = 32;

    public byte[] generate(char[] password, int c, int dkLen) {

        byte[] tmp = new byte[password.length << 1];

        for (int i = 0; i < password.length; i++) {
            tmp[i << 1] = (byte) (password[i] & 0xFF);
            tmp[(i << 1) + 1] = (byte) ((password[i] >> 8) & 0xFF);
        }

        return generate(tmp, c, dkLen);
    }

    public byte[] generate(byte[] password, int c, int dkLen) {
        byte[] salt = new byte[16];
        rand.nextBytes(salt);

        return generate(password, salt, c, dkLen);
    }

    public byte[] generate(byte[] password, byte[] salt, int c, int dkLen) {
        int l =  Math.ceilDiv(dkLen, hLen);
        byte[] DK = new byte[(l << 5)];
        int dkoffset = 0;

        for (int i = 1; i <= l; i++) {
            System.arraycopy(F(password, salt, c, i), 0, DK, dkoffset, 32);
            dkoffset += 32;
        }

        return DK;
    }

    private byte[] F(byte[] password, byte[] salt, int c, int i) {
        byte[] U = new byte[hLen];
        byte[] message = new byte[salt.length + 4];

        System.arraycopy(salt,0, message, 0, salt.length);
        System.arraycopy(int_32_BE(i), 0, message, salt.length, 4);

        message = hmac.generate(message, password, 64);
        System.arraycopy(message, 0, U, 0, hLen);

        for (int j = 1; j < c; j++) {
            message = hmac.generate(message, password, 64);
            array_xor(U, U, message);
        }

        return U;
    }

    private void array_xor(byte[] buff, byte[] a, byte[] b) {
        for (int i = 0; i < a.length; i++) {
            buff[i] = (byte) (a[i] ^ b[i]);
        }
    }

    private byte[] int_32_BE(int i) {
        return new byte[]{(byte) ((i >> 24) & 0xFF), (byte) ((i >> 16) & 0xFF), (byte) ((i >> 8) & 0xFF), (byte) (i & 0xFF)};
    }
}
