package passwordmanager.crypt.kdf.scrypt;

public class salsa20_core {

    private static int leftrotate(int word, int n) {
        return (word << n) | (word >>> (32 - n));
    }

    private static void QR(int[] x, int a, int b, int c, int d) {
        x[b] ^= leftrotate((x[a] + x[d]), 7);
        x[c] ^= leftrotate((x[b] + x[a]), 9);
        x[d] ^= leftrotate((x[c] + x[b]), 13);
        x[a] ^= leftrotate((x[d] + x[c]), 18);
    }

    public static void salsa20_block(int[] out, int[] in, int rounds) {
        int[] x = new int[16];
        System.arraycopy(in, 0, x, 0, 16);

        for (int i = 0; i < rounds; i += 2) {
            QR(x, 0, 4, 8, 12);
            QR(x, 5, 9, 13, 1);
            QR(x, 10, 14, 2, 6);
            QR(x, 15, 3, 7, 11);

            QR(x, 0, 1, 2, 3);
            QR(x,5, 6, 7, 4);
            QR(x, 10, 11, 8, 9);
            QR(x, 15, 12, 13, 14);
        }

        for (int i = 0; i < 16; i++) {
            out[i] = in[i] + x[i];
        }
    }
}
