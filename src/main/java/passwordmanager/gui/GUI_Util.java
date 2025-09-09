package passwordmanager.gui;

import passwordmanager.crypt.cipher.aes.InvalidKeyException;

import java.util.Base64;

public class GUI_Util {

    static String serialize(int[] ints) {
        return Base64.getUrlEncoder().encodeToString(GUI_Util.toBytes(ints));
    }
    static String serialize(byte[] ints) {
        return Base64.getUrlEncoder().encodeToString(ints);
    }
    static byte[] deserialize(String base) {
        return Base64.getUrlDecoder().decode(base);
    }

    static void zeroArray(char[] a) {
        if(a == null) return;

        for (int i = 0; i < a.length; i++) {
            a[i] = 0;
        }
    }

    static void zeroArray(byte[] a) {
        if(a == null) return;

        for (int i = 0; i < a.length; i++) {
            a[i] = 0;
        }
    }

    static void zeroArray(int[] a) {
        if(a == null) return;

        for (int i = 0; i < a.length; i++) {
            a[i] = 0;
        }
    }

    static byte[] toBytes(int[] a) {
        byte[] o = new byte[a.length << 2];

        for (int i = 0; i < a.length; i++) {
            o[(i << 2)] = (byte) (a[i] & 0xFF);
            o[(i << 2) + 1] = (byte) ((a[i] >> 8) & 0xFF);
            o[(i << 2) + 2] = (byte) ((a[i] >> 16) & 0xFF);
            o[(i << 2) + 3] = (byte) ((a[i] >> 24) & 0xFF);
        }

        return o;
    }

    static String bytes_to_string(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }

    static int[] bytes_to_ints(byte[] bytes) {
        if((bytes.length & 3) != 0) {
            throw new InvalidKeyException();
        }

        int[] ints = new int[bytes.length / 4];

        for (int i = 0; i < ints.length; i++) {
            ints[i] = (bytes[(i << 2)] & 0xFF) | ((bytes[(i << 2) + 1] & 0xFF) << 8) | ((bytes[(i << 2) + 2] & 0xFF) << 16) | ((bytes[(i << 2) + 3] & 0xFF) << 24);
        }

        return ints;
    }

    static byte[] toBytes(int i) {
        byte[] bytes = new byte[4];

        bytes[0] = (byte) (i & 0xFF);
        bytes[1] = (byte) ((i >> 8) & 0xFF);
        bytes[2] = (byte) ((i >> 16) & 0xFF);
        bytes[3] = (byte) ((i >> 24) & 0xFF);

        return bytes;
    }

    static byte[] toBytes(char[] c) {
        byte[] b = new byte[c.length << 1];

        for (int i = 0; i < c.length; i++) {
            b[(i << 1)] = (byte) (c[i] & 0xFF);
            b[(i << 1) + 1] = (byte) ((c[i] >> 8) & 0xFF);
        }

        return b;
    }

    static byte[] toBytes(char[] c, int from, int to) {
        byte[] b = new byte[(to - from) << 1];

        for (int i = from; i < to; i++) {
            b[(i << 1)] = (byte) (c[i] & 0xFF);
            b[(i << 1) + 1] = (byte) ((c[i] >> 8) & 0xFF);
        }

        return b;
    }

    static int toInt(byte[] b) {
        return b[0] & 0xFF | ((b[1] & 0xFF) << 8) | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24);
    }


    static int toInt(char[] b) {
        return b[0] & 0xFFFF | ((b[1] & 0xFFFF) << 16);
    }

    static char[] toChars(int i) {
        return new char[]{(char) (i & 0xFFFF), (char) ((i >> 16) & 0xFFFF)};
    }

    static boolean safeCmp(byte[] one, byte[] two) {
        if(one.length != two.length) return false;

        int d = 0;

        for (int i = 0; i < one.length; i++) {
            d |= one[i] ^ two[i];
        }

        return d == 0;
    }

    static boolean safeCmp(char[] one, char[] two) {
        if(one.length != two.length) return false;

        int d = 0;

        for (int i = 0; i < one.length; i++) {
            d |= one[i] ^ two[i];
        }

        return d == 0;
    }

    static char[] toChars(byte[] bytes) {

        if((bytes.length & 1) == 1) throw new IllegalArgumentException();

        char[] chars = new char[bytes.length >> 1];

        for (int i = 0; i < chars.length; i++) {
            chars[i] = (char) (bytes[(i << 1)] & 0xFF | (bytes[(i << 1) + 1] & 0xFF) << 8);
        }

        return chars;
    }

    static char[] merge(char[] a, char[] b) {
        char[] m = new char[a.length + b.length];
        System.arraycopy(a, 0, m, 0, a.length);
        System.arraycopy(b, 0, m, a.length, b.length);
        return m;
    }

    static char[] subarray(char[] array, int from, int to) {
        char[] o = new char[to - from];
        System.arraycopy(array, from, o, 0, to - from);
        return o;
    }

    static byte[] string_to_bytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len >> 1];

        for (int i = 0; i < len; i += 2) {
            data[i >> 1] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    static String bytesToHexString(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }
}
