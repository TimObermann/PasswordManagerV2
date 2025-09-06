package passwordmanager.crypt.cipher.chacha;

import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

public class ChaCha {

    private final int ROUNDS;
    private final int parallelization;

    public ChaCha(int rounds) {
        this.ROUNDS = rounds;
        this.parallelization = 1;
    }

    public ChaCha(int rounds, int parallelization) {
        this.ROUNDS = rounds;
        this.parallelization = parallelization;
    }

    public int getRounds() {
        return ROUNDS;
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

    private int[] init_state(int[] key, int counter, int[] nonce) {

        int[] state = new int[16];

        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        System.arraycopy(key, 0, state, 4, 8);

        state[12] = counter;

        System.arraycopy(nonce, 0, state, 13, 3);

        return state;
    }

    protected void chacha_block(int[] key, int counter, int[] nonce, byte[] out) {

        int[] state = init_state(key, counter, nonce);

        int[] x = new int[16];
        System.arraycopy(state, 0, x, 0, 16);

        for (int i = 0; i < ROUNDS; i += 2) {

                QR(x, 0, 4, 8, 12);
                QR(x, 1, 5, 9, 13);
                QR(x, 2, 6, 10, 14);
                QR(x, 3, 7, 11, 15);

                QR(x, 0, 5, 10, 15);
                QR(x, 1, 6, 11, 12);
                QR(x, 2, 7, 8, 13);
                QR(x, 3, 4, 9,14);

        }

        for (int i = 0; i < 16; i++) {
            int v = state[i] + x[i];

            out[(i << 2)] = (byte) (v & 0xFF);
            out[(i << 2) + 1] = (byte) ((v >> 8) & 0xFF);
            out[(i << 2) + 2] = (byte) ((v >> 16) & 0xFF);
            out[(i << 2) + 3] = (byte) ((v >> 24) & 0xFF);
        }
    }

    protected void chacha_block(int[] state, int[] out) {

        int[] x = new int[16];
        System.arraycopy(state, 0, x, 0, 16);

        for (int i = 0; i < ROUNDS; i += 2) {

            QR(x, 0, 4, 8, 12);
            QR(x, 1, 5, 9, 13);
            QR(x, 2, 6, 10, 14);
            QR(x, 3, 7, 11, 15);

            QR(x, 0, 5, 10, 15);
            QR(x, 1, 6, 11, 12);
            QR(x, 2, 7, 8, 13);
            QR(x, 3, 4, 9,14);

        }

        for (int i = 0; i < 16; i++) {
            out[i] = state[i] + x[i];
        }
    }

    private byte[] chacha_block_multiple(byte[] plaintext_slice, int[] key, int fromBlock, int toBlock, int init_counter, int[] nonce, boolean hasLast) {
        byte[] key_stream = new byte[64];
        byte[] ciphertext_slice = new byte[plaintext_slice.length];

        toBlock = hasLast ? toBlock - 1 : toBlock;

        for (int i = fromBlock; i <= toBlock; i++) {
            chacha_block(key, init_counter + i, nonce, key_stream);

            for (int j = 0; j < 64; j++) {
                ciphertext_slice[(i - fromBlock << 6) + j] = (byte) (plaintext_slice[(i - fromBlock << 6) + j] ^ key_stream[j]);
            }
        }

        if(hasLast && (plaintext_slice.length & 63) != 0) {
            chacha_block(key, init_counter + toBlock + 1, nonce, key_stream);

            int c = 0;
            for (int i = ((toBlock + 1 - fromBlock) << 6); i < plaintext_slice.length; i++) {
                ciphertext_slice[i] = (byte) (plaintext_slice[i] ^ key_stream[c++]);
            }
        }

        return ciphertext_slice;
    }

    public byte[] chacha_encrypt(byte[] plaintext, int[] key, int init_counter, int[] nonce) {

        byte[] ciphertext = new byte[plaintext.length];

        int block_count = (plaintext.length >> 6);
        int blocks_per_thread = block_count / parallelization;

        byte[] key_stream = new byte[64];

        if(parallelization == 1 || blocks_per_thread <= 1) {
            for (int i = 0; i < block_count; i++) {
                chacha_block(key, init_counter + i, nonce, key_stream);

                for (int j = 0; j < 64; j++) {
                    ciphertext[(i << 6) + j] = (byte) (plaintext[(i << 6) + j] ^ key_stream[j]);
                }
            }

            if((plaintext.length & 63) != 0) {
                chacha_block(key, init_counter + block_count, nonce, key_stream);

                int c = 0;
                for (int i = ((block_count) << 6); i < plaintext.length; i++) {
                    ciphertext[i] = (byte) (plaintext[i] ^ key_stream[c++]);
                }
            }
        }
        else {
            ExecutorService pool = Executors.newFixedThreadPool(parallelization);
            Future<byte[]>[] slices = new Future[parallelization];

            for (int i = 0; i < parallelization - 1; i++) {
                byte[] slice = new byte[blocks_per_thread << 6];
                System.arraycopy(plaintext, (slice.length * i), slice, 0, slice.length);

                int start = i * blocks_per_thread;

                Callable<byte[]> call = () -> chacha_block_multiple(slice, key, start, start + blocks_per_thread - 1, init_counter, nonce, false);

                slices[i] = pool.submit(call);
            }

            if((plaintext.length & 63) != 0) {
                byte[] slice = new byte[plaintext.length - (((parallelization - 1) * blocks_per_thread) << 6)];
                System.arraycopy(plaintext, plaintext.length - slice.length, slice, 0, slice.length);

                int start = (plaintext.length >> 6) - 1;
                Callable<byte[]> call = () -> chacha_block_multiple(slice, key, start, start + blocks_per_thread + 1, init_counter, nonce, true);

                slices[parallelization - 1] = pool.submit(call);
            }

            int index = 0;
            for (Future<byte[]> slice : slices) {
                try {
                    byte[] ciphertext_slice = slice.get();
                    System.arraycopy(ciphertext_slice, 0, ciphertext, index, ciphertext_slice.length);
                    index += ciphertext_slice.length;
                } catch (Exception e) {
                    pool.shutdown();

                    throw new RuntimeException();
                }
            }

            pool.shutdown();
        }

        return ciphertext;
    }

    public byte[] encrypt(byte[] plaintext, int[] key, int initial_counter, int[] nonce) {
        return chacha_encrypt(plaintext, key, initial_counter, nonce);
    }

    public byte[] decrypt(byte[] ciphertext, int[] key, int initial_counter, int[] nonce) {
        return chacha_encrypt(ciphertext, key, initial_counter, nonce);
    }
}
