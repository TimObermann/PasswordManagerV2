package passwordmanager.crypt.kdf.argon2;

import passwordmanager.crypt.hash.Blake2b;

public class Argon2 {


    //THERE ARE SOOOOO MANY ISSUES WITH THIS!!!!
    //I GIVE UP
    //maybe later...


    public Argon2() {
        hash = new Blake2b(64);
    }

    private final Blake2b hash;
    private final int R1 = 32;
    private final int R2 = 24;
    private final int R3 = 16;
    private final int R4 = 63;
    private final byte[] firstBlock = new byte[4];
    private final byte[] secondBlock = new byte[4];
    private final byte[] Z = new byte[48];
    private final byte[] buff = new byte[1024];
    private final long[] Y = new long[128];
    private final long[] zeros = new long[128];
    private long[] slice_stream;
    private int slice_stream_index;
    private final int SL = 4;

    public byte[] argon2(byte[] password, byte[] salt, byte[] key, byte[] associatedData, int parallelism, int tagLength, int memSizeKiB, int iterations, int version, ARGON2_TYPE type) {
        hash.insert(int_to_bytes(parallelism));
        hash.insert(int_to_bytes(tagLength));
        hash.insert(int_to_bytes(memSizeKiB));
        hash.insert(int_to_bytes(iterations));
        hash.insert(int_to_bytes(version));
        hash.insert(type_to_bytes(type));
        hash.insert(int_to_bytes(password.length));
        hash.insert(password);
        hash.insert(int_to_bytes(salt.length));
        hash.insert(salt);
        hash.insert(int_to_bytes(key.length));
        hash.insert(key);
        hash.insert(int_to_bytes(associatedData.length));
        hash.insert(associatedData);

        byte[] H_0 = hash.generate();

        int memoryBlocks = (parallelism << 2) * Math.floorDiv(memSizeKiB, (parallelism << 2));
        int q = memoryBlocks / parallelism;

        byte[][][] B = new byte[parallelism][q][1024];

        byte[] Hconcat = new byte[H_0.length + 8];
        System.arraycopy(H_0, 0, Hconcat, 0, H_0.length);
        for (int i = 0; i < parallelism; i++) {
            System.arraycopy(int_to_bytes(0),0, Hconcat, H_0.length, 4);
            System.arraycopy(int_to_bytes(i),0, Hconcat, H_0.length + 4, 4);

            B[i][0] = variable_size_hash_function(Hconcat, 1024);

            System.arraycopy(int_to_bytes(1),0, Hconcat, H_0.length, 4);
            B[i][1] = variable_size_hash_function(Hconcat, 1024);
        }

        long[] X = new long[128];
        long[] Y = new long[128];
        byte[] result = new byte[1024];
        final int slice_length = q / SL;

        for (int i = 0; i < parallelism; i++) {
            for (int j = 2; j < q; j++) {
                int[] tmp = getBlockIndex(type, i, j, q, parallelism, B, j/(slice_length), 0, i, memSizeKiB, iterations, (j % slice_length == 0));
                int istar = tmp[0];
                int jstar = tmp[1];

                inPlaceBytesToLongs(B[i][j-1], X);
                inPlaceBytesToLongs(B[istar][jstar], Y);

                longs_to_bytes(G(X, Y), result);
                System.arraycopy(result, 0, B[i][j], 0, result.length);
            }
        }

        for (int nIteration = 1; nIteration < iterations; nIteration++) {
            for (int i = 0; i < parallelism; i++) {
                for (int j = 0; j < q; j++) {

                    int[] tmp = getBlockIndex(type, i, j, q, parallelism, B, (j/slice_length),  nIteration, i, memSizeKiB, iterations, (j % slice_length == 0));
                    int istar = tmp[0];
                    int jstar = tmp[1];

                    if(j == 0) {
                        inPlaceBytesToLongs(B[i][q-1], X);
                        inPlaceBytesToLongs(B[istar][jstar], Y);

                        longs_to_bytes_withXOR(G(X, Y), B[i][0]);
                    }
                    else {
                        inPlaceBytesToLongs(B[i][j-1], X);
                        inPlaceBytesToLongs(B[istar][jstar], Y);

                        longs_to_bytes_withXOR(G(X, Y), B[i][j]);
                    }
                }
            }
        }

        byte[] C = B[0][q-1];
        for (int i = 1; i < parallelism; i++) {
            array_xor(C, C, B[i][q-1]);
        }

        return variable_size_hash_function(C, tagLength);
    }

    private void calculateStreamForSlice(int q, long sl, long r, long l, long m, long t, ARGON2_TYPE type) {
        slice_stream = new long[(q / (SL << 7)) << 7];

        System.arraycopy(long_to_bytes(r), 0, Z, 0, 8);
        System.arraycopy(long_to_bytes(l), 0, Z, 8, 8);
        System.arraycopy(long_to_bytes(sl), 0, Z, 16, 8);
        System.arraycopy(long_to_bytes(m), 0, Z, 24, 8);
        System.arraycopy(long_to_bytes(t), 0, Z, 32, 8);
        System.arraycopy(type_to_long_bytes(type), 0, Z, 40, 8);


        for (long k = 1; k <= (long) q / (SL << 7); k++) {
            System.arraycopy(Z, 0, buff, 0, Z.length);
            System.arraycopy(long_to_bytes(k), 0, buff, Z.length, 8);
            inPlaceBytesToLongs(buff, Y);

            System.arraycopy(G(zeros, G(zeros, Y)), 0, slice_stream, ((int)(k-1) << 7), 128);
        }

        slice_stream_index = 0;
    }

    private int[] getBlockIndex(ARGON2_TYPE type, int i, int j, int q, int p, byte[][][] B, long sl, long r, long l, long m, long t, boolean newSlice) {
        int[] J1_J2 = switch (type) {
            case ARGON2_d -> {
                System.arraycopy(B[i][j-1], 0, firstBlock,0, 4);
                System.arraycopy(B[i][j-1], 4, secondBlock,0, 4);

                yield new int[]{(int)(bytes_to_int(firstBlock) & 0xFFFFFFFFL), (int)(bytes_to_int(secondBlock) & 0xFFFFFFFFL)};
            }
            case ARGON2_i -> {

                if(newSlice) {
                    calculateStreamForSlice(q, sl, r, l, m, t, type);
                }

                long X1_X2 = slice_stream[slice_stream_index++];

                yield new int[]{(int)(X1_X2 & 0xFFFFFFFFL), (int)((X1_X2 >> 32) & 0xFFFFFFFFL)};
            }
            case ARGON2_id -> {
                if(r == 0 && (sl == 0 || sl == 1)) {
                    if(newSlice) {
                        calculateStreamForSlice(q, sl, r, l, m, t, type);
                    }

                    long X1_X2 = slice_stream[slice_stream_index++];

                    yield new int[]{(int)(X1_X2 & 0xFFFFFFFFL), (int)((X1_X2 >> 32) & 0xFFFFFFFFL)};
                }
                else {
                    System.arraycopy(B[i][j-1], 0, firstBlock,0, 4);
                    System.arraycopy(B[i][j-1], 4, secondBlock,0, 4);

                    yield new int[]{bytes_to_int(firstBlock), bytes_to_int(secondBlock)};
                }
            }
        };

        int lane = (int)((J1_J2[1] & 0xFFFFFFFFL) % p);

        if(r == 0 && sl == 0){
            lane = (int) (l & 0xFFFFFFFFL);
        }

        long Wsize = 0;
        if(lane == l) {
            Wsize = j - 1;
        }
        else {
            if(r == 0) {
                Wsize = sl * (q/SL);
            }
            else {
                Wsize = (SL - 1) * (q / SL);
            }
        }

        if(Wsize == 0) {
            return new int[]{(int) l, j - 1};
        }

        long x = ((long) J1_J2[0] * J1_J2[0]) >> 32;
        long y = (Wsize * x) >> 32;
        long z = Wsize - 1 - y;

        int start_pos = (r == 0) ? 0 : ((int) ((sl & 0xFFFFFFFFL) + 1) % SL) * (q / SL);
        if(l == lane) start_pos = 0;

        int block = (int) ((start_pos + z) % q);

        return new int[]{lane, block};
    }


    private long[] G(long[] X, long[] Y) {
        long[] R = new long[X.length];

        array_xor(R, X, Y);

        long[] tmp = new long[R.length];
        System.arraycopy(R, 0, tmp, 0, R.length);

        for (int i = 0; i < 8; i++) {
            P(R, (i << 4));
        }

        long[] column = new long[16];
        for (int i = 0; i < 16; i++) {
            fetch_column(column, R, i);
            P(column, 0);
            scatter_column(column, R, i);
        }

        array_xor(R, R, tmp);

        return R;
    }

    private void P(long[] R_i, int offset) {
        GB(R_i, offset, offset + 4, offset + 8, offset + 12);
        GB(R_i, offset + 1, offset + 5, offset + 9, offset + 13);
        GB(R_i, offset + 2, offset + 6, offset + 10, offset + 14);
        GB(R_i, offset + 3, offset + 7, offset + 11, offset + 15);

        GB(R_i, offset, offset + 5, offset + 10, offset + 15);
        GB(R_i, offset + 1, offset + 6, offset + 11, offset + 12);
        GB(R_i, offset + 2, offset + 7, offset + 8, offset + 13);
        GB(R_i, offset + 3, offset + 4, offset + 9, offset + 14);
    }

    private void GB(long[] v, int a, int b, int c, int d) {
        v[a] = (v[a] + v[b] + 2L * (v[a] & 0xFFFFFFFFL) * (v[b] & 0xFFFFFFFFL));
        v[d] = rightrotate((v[d] ^ v[a]), R1);
        v[c] = v[c] + v[d] + 2L * (v[c] & 0xFFFFFFFFL) * (v[d] & 0xFFFFFFFFL);
        v[b] = rightrotate((v[b] ^ v[c]), R2);

        v[a] = v[a] + v[b] + 2L * (v[a] & 0xFFFFFFFFL) * (v[b] & 0xFFFFFFFFL);
        v[d] = rightrotate((v[d] ^ v[a]), R3);
        v[c] = v[c] + v[d] + 2L * (v[c] & 0xFFFFFFFFL) * (v[d] & 0xFFFFFFFFL);
        v[b] = rightrotate((v[b] ^ v[c]), R4);
    }

    private byte[] perform_small_blake(byte[] message, int hash_size) {

        byte[] message_with_size = new byte[message.length + 4];
        System.arraycopy(message, 0, message_with_size, 4, message.length);

        message_with_size[0] = (byte) (hash_size & 0xFF);
        message_with_size[1] = (byte) ((hash_size >> 8) & 0xFF);
        message_with_size[2] = (byte) ((hash_size >> 16) & 0xFF);
        message_with_size[3] = (byte) ((hash_size >> 24) & 0xFF);

        return Blake2b.hash(new byte[0], message_with_size, (byte) hash_size);
    }

    private byte[] variable_size_hash_function(byte[] message, int hash_size) {
        if(hash_size <= 64) {
            return perform_small_blake(message, hash_size);
        }

        int r = Math.ceilDiv(hash_size, 32) - 1;
        byte[] buff = perform_small_blake(message, 64);
        byte[] A = new byte[hash_size];
        int Aindex = 0;

        System.arraycopy(buff, 0, A, Aindex, 32);
        Aindex += 32;

        for (int i = 2; i <= r; i++) {
            buff = (Blake2b.hash(new byte[0], buff, (byte) 64));
            System.arraycopy(buff, 0, A, Aindex, 32);
            Aindex += 32;
        }

        int partial_bytes_needed = hash_size - (r << 5);

        if(partial_bytes_needed > 0) {
            buff = Blake2b.hash(new byte[0], buff, (byte) partial_bytes_needed);
            System.arraycopy(buff, 0, A, Aindex, partial_bytes_needed);
        }

        return A;
    }

    private byte[] type_to_bytes(ARGON2_TYPE type) {
        return switch (type) {
            case ARGON2_d  -> new byte[]{(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00};
            case ARGON2_i  -> new byte[]{(byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00};
            case ARGON2_id -> new byte[]{(byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00};
        };
    }

    private byte[] type_to_long_bytes(ARGON2_TYPE type) {
        return switch (type) {
            case ARGON2_d  -> new byte[]{(byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00};
            case ARGON2_i  -> new byte[]{(byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00};
            case ARGON2_id -> new byte[]{(byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x00};
        };
    }

    private int bytes_to_int(byte[] b) {
        return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8) | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24);
    }

    private byte[] int_to_bytes(int i) {
        return new byte[] {(byte) (i & 0xFF), (byte) ((i >> 8) & 0xFF), (byte) ((i >> 16) & 0xFF), (byte) ((i >> 24) & 0xFF)};
    }

    private byte[] long_to_bytes(long l) {
        return new byte[] {(byte) (l & 0xFF), (byte) ((l >> 8) & 0xFF), (byte) ((l >> 16) & 0xFF), (byte) ((l >> 24) & 0xFF), (byte) ((l >> 32) & 0xFF), (byte) ((l >> 40) & 0xFF), (byte) ((l >> 48) & 0xFF), (byte) ((l >> 56) & 0xFF)};
    }

    private long rightrotate(long word, int n) {
        return word >>> n | ((word & ((1L << n) - 1)) << (64 - n));
    }

    private void array_xor(long[] buff, long[] a, long[] b) {
        for (int i = 0; i < a.length; i++) {
            buff[i] = a[i] ^ b[i];
        }
    }

    private void array_xor(byte[] buff, byte[] a, byte[] b) {
        for (int i = 0; i < a.length; i++) {
            buff[i] = (byte) (a[i] ^ b[i]);
        }
    }

    private void fetch_column(long[] col, long[] R, int i) {
        for (int j = 0; j < 8; j++) {
            col[j] = R[(j << 4) + i];
            col[j + 8] = R[(j << 4) + ((i + 8) & 15)];
        }
    }

    private void scatter_column(long[] col, long[] R, int i) {
        for (int j = 0; j < 8; j++) {
            R[(j << 4) + i] = col[j];
            R[(j << 4) + ((i + 8) & 15)] = col[j + 8];
        }
    }

    private void inPlaceBytesToLongs(byte[] b, long[] l) {
        for (int i = 0; i < l.length; i++) {
            l[i] = (b[i << 3] & 0xFF) | ((long) b[(i << 3) + 1] & 0xFF) << 8 | ((long) b[(i << 3) + 2] & 0xFF) << 16 | ((long) b[(i << 3) + 3] & 0xFF) << 24
                    | ((long) b[(i << 3) + 4] & 0xFF) << 32 | ((long) b[(i << 3) + 5] & 0xFF) << 40 | ((long) b[(i << 3) + 6] & 0xFF) << 48
                    | ((long) b[(i << 3) + 7] & 0xFF) << 56;
        }
    }

    private void longs_to_bytes(long[] l, byte[] b) {
        for (int i = 0; i < l.length; i++) {
            b[(i << 3)] = (byte) (l[i] & 0xFF);
            b[(i << 3) + 1] = (byte) ((l[i] >> 8) & 0xFF);
            b[(i << 3) + 2] = (byte) ((l[i] >> 16) & 0xFF);
            b[(i << 3) + 3] = (byte) ((l[i] >> 24) & 0xFF);
            b[(i << 3) + 4] = (byte) ((l[i] >> 32) & 0xFF);
            b[(i << 3) + 5] = (byte) ((l[i] >> 40) & 0xFF);
            b[(i << 3) + 6] = (byte) ((l[i] >> 48) & 0xFF);
            b[(i << 3) + 7] = (byte) ((l[i] >> 56) & 0xFF);
        }
    }

    private void longs_to_bytes_withXOR(long[] l, byte[] b) {
        for (int i = 0; i < l.length; i++) {
            b[(i << 3)] ^= (byte) (l[i] & 0xFF);
            b[(i << 3) + 1] ^= (byte) ((l[i] >> 8) & 0xFF);
            b[(i << 3) + 2] ^= (byte) ((l[i] >> 16) & 0xFF);
            b[(i << 3) + 3] ^= (byte) ((l[i] >> 24) & 0xFF);
            b[(i << 3) + 4] ^= (byte) ((l[i] >> 32) & 0xFF);
            b[(i << 3) + 5] ^= (byte) ((l[i] >> 40) & 0xFF);
            b[(i << 3) + 6] ^= (byte) ((l[i] >> 48) & 0xFF);
            b[(i << 3) + 7] ^= (byte) ((l[i] >> 56) & 0xFF);
        }
    }
}