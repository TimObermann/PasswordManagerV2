package passwordmanager.crypt.cipher.chacha;

import java.security.SecureRandom;

public class XChaCha {

    private final ChaCha chaCha;

    public XChaCha(int rounds) {
        chaCha = new ChaCha(rounds);
    }

    public XChaCha(int rounds, int parallelization) {
        chaCha = new ChaCha(rounds, parallelization);
    }

    private int leftrotate(int word, int n) {
        return (word << n) | (word >>> (32 - n));
    }

    private void QR(int[] x, int a, int b, int c, int d) {
        x[a] += x[b]; x[d] ^= x[a]; x[d] = leftrotate(x[d], 16);
        x[c] += x[d]; x[b] ^= x[c]; x[b] = leftrotate(x[b], 12);
        x[a] += x[b]; x[d] ^= x[a]; x[d] = leftrotate(x[d], 8);
        x[c] += x[d]; x[b] ^= x[c]; x[b] = leftrotate(x[b], 7);
    }

    public int[] HChaCha(int[] key, int[] nonce_128) {
        int[] state = new int[16];
        int[] result = new int[8];

        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        System.arraycopy(key, 0, state, 4, 8);
        System.arraycopy(nonce_128, 0, state, 12, 4);

        for (int i = 0; i < chaCha.getRounds(); i += 2) {

            QR(state, 0, 4, 8, 12);
            QR(state, 1, 5, 9, 13);
            QR(state, 2, 6, 10, 14);
            QR(state, 3, 7, 11, 15);

            QR(state, 0, 5, 10, 15);
            QR(state, 1, 6, 11, 12);
            QR(state, 2, 7, 8, 13);
            QR(state, 3, 4, 9,14);

        }

        System.arraycopy(state, 0, result, 0, 4);
        System.arraycopy(state, 12, result, 4, 4);

        return result;
    }

    public byte[] encrypt(byte[] plaintext, int[] key, int init_counter, int[] nonce) {

        int[] true_nonce = new int[3];
        int[] smallNonce = new int[4];

        System.arraycopy(nonce, 0, smallNonce, 0, 4);
        System.arraycopy(nonce, 4, true_nonce, 1, 2);

        int[] subkey = HChaCha(key, smallNonce);

        return chaCha.chacha_encrypt(plaintext, subkey, init_counter, true_nonce);
    }
}
