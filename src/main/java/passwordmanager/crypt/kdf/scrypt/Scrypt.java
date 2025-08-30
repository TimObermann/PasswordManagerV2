package passwordmanager.crypt.kdf.scrypt;

import passwordmanager.crypt.kdf.PBKDF2;

import java.util.concurrent.*;

public class Scrypt {

    private final PBKDF2 pbkdf2 = new PBKDF2();


    public byte[] scrypt(byte[] password, byte[] salt, int N, int blockSizeFactor, int parallelization, int dkLen) {

        if(N <= 0 || (N & (N - 1)) != 0) {
            throw new IllegalArgumentException("cost (N) " + N + " must be a power of two greater than 0");
        }

        if(password == null) {
            throw new IllegalArgumentException("password must not be null");
        }
        if(salt == null) {
            throw new IllegalArgumentException("salt must not be null");
        }
        if(parallelization <= 0) {
            throw new IllegalArgumentException("parallelization must not a value larger than zero");
        }

        int blockSize = (blockSizeFactor << 7);
        int cost = Integer.numberOfTrailingZeros(N);

        byte[] B = pbkdf2.generate(password, salt, 1, blockSize * parallelization);
        byte[] out = new byte[dkLen];
        byte[] expensiveSalt = new byte[B.length];

        if (parallelization > 1) {
            ExecutorService pool = Executors.newFixedThreadPool(parallelization);
            Future<byte[]>[] futures = new Future[parallelization];

            for (int i = 0; i < parallelization; i++) {
                byte[] block = new byte[blockSize];
                System.arraycopy(B, blockSize * i, block, 0, blockSize);

                Callable<byte[]> call = () -> ROMix(block, cost);
                futures[i] = pool.submit(call);
            }

            int index = 0;
            for (int i = 0; i < parallelization; i++) {
                try {
                    byte[] block = futures[i].get();
                    System.arraycopy(block, 0, expensiveSalt, index, block.length);
                    index += block.length;
                } catch (Exception e) {
                    throw new RuntimeException();
                }
            }

            pool.shutdown();
        } else {
            expensiveSalt = ROMix(B, cost);
        }

        return pbkdf2.generate(password, expensiveSalt, 1, dkLen);

    }

    private byte[] ROMix(byte[] block, int N) {

        int iterations = (1 << N);

        byte[] X = new byte[block.length];
        byte[] Y = new byte[X.length];
        byte[][] V = new byte[iterations][X.length];

        System.arraycopy(block, 0, X, 0, X.length);

        for (int i = 0; i < iterations; i++) {
            System.arraycopy(X, 0, V[i], 0, X.length);
            BlockMix(V[i], X);
        }

        int j;
        int bytes = (N + 7) >> 3;

        for (int i = 0; i < iterations; i++) {
            j = Integerify(X, bytes) & (iterations - 1);
            array_xor(Y, X, V[j]);
            BlockMix(Y, X);
        }

        return X;
    }

    private int Integerify(byte[] X, int bytes) {
        int o = 0;
        for (int i = 0; i < bytes; i++) {
            o |= (X[X.length - 64 + i] & 0xFF) << (i << 3);
        }
        return o;
    }

    private void BlockMix(byte[] B, byte[] out) {
        int r = (B.length >> 7);

        byte[] current_block = new byte[64];
        int[] X = new int[16];
        int index;

        System.arraycopy(B, B.length - current_block.length, current_block, 0, current_block.length);

        bytes_to_ints(current_block, X);
        for (int i = 0; i < (r << 1); i++) {
            System.arraycopy(B, (i << 6), current_block, 0, current_block.length);

            array_xor(X, X, current_block);

            salsa20_core.salsa20_block(X, X, 8);

            ints_to_bytes(X, current_block);

            if ((i & 1) == 0) {
                index = i >> 1;
            } else {
                index = r + ((i - 1) >> 1);
            }

            System.arraycopy(current_block, 0, out, (index << 6), current_block.length);
        }
    }

    private void bytes_to_ints(byte[] in, int[] out) {
        for (int i = 0; i < out.length; i++) {
            out[i] = (in[(i << 2)] & 0xFF)
                    | ((in[(i << 2) + 1] & 0xFF) << 8)
                    | ((in[(i << 2) + 2] & 0xFF) << 16)
                    | ((in[(i << 2) + 3] & 0xFF) << 24);
        }
    }

    private void ints_to_bytes(int[] in, byte[] out) {
        for (int i = 0; i < in.length; i++) {
            out[(i << 2)] = (byte) (in[i] & 0xFF);
            out[(i << 2) + 1] = (byte) ((in[i] >> 8) & 0xFF);
            out[(i << 2) + 2] = (byte) ((in[i] >> 16) & 0xFF);
            out[(i << 2) + 3] = (byte) ((in[i] >> 24) & 0xFF);
        }
    }

    private int bytes_to_int(byte[] in, int offset) {
        return (in[(offset)] & 0xFF)
                | ((in[(offset) + 1] & 0xFF) << 8)
                | ((in[(offset) + 2] & 0xFF) << 16)
                | ((in[(offset) + 3] & 0xFF) << 24);
    }

    private void array_xor(byte[] out, byte[] in_one, byte[] in_two) {
        for (int i = 0; i < in_one.length; i++) {
            out[i] = (byte) (in_one[i] ^ in_two[i]);
        }
    }

    private void array_xor(int[] out, int[] inI, byte[] inB) {
        for (int i = 0; i < inI.length; i++) {
            out[i] = inI[i] ^ bytes_to_int(inB, (i << 2));
        }
    }

}
