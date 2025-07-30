package passwordmanager.api.SHA2;

import java.util.Arrays;

public class SHA2 {

    private final int[] h_init = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };

    private int h0 = h_init[0];
    private int h1 = h_init[1];
    private int h2 = h_init[2];
    private int h3 = h_init[3];
    private int h4 = h_init[4];
    private int h5 = h_init[5];
    private int h6 = h_init[6];
    private int h7 = h_init[7];


    private final int[] k = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    private int[] message_schedule;
    private byte[] message;
    private int message_len;
    private int message_offset;

    public SHA2() {
        message = new byte[64];
        message_len = 0;
        message_offset = 0;
    }

    public void insert(byte[] b) {
        message_len += b.length;
        int b_offset = 0;

        while (b_offset < b.length) {

            int copy_bytes = Math.min(64 - message_offset, b.length - b_offset);

            System.arraycopy(b, b_offset, message, message_offset, copy_bytes);

            b_offset += copy_bytes;
            message_offset += copy_bytes;

            if(message_offset == 64) {
                process_block(message);
                compress();
                message_offset = 0;
            }
        }
    }

    private void process_block(byte[] block) {
        message_schedule = new int[64];

        for (int i = 0; i < 16; i++) {
            message_schedule[i] = (block[(i << 2) + 3] & 0xFF) | ((block[(i << 2) + 2] & 0xFF) << 8) | ((block[(i << 2) + 1] & 0xFF) << 16) | ((block[(i << 2)] & 0xFF) << 24);
        }

        for (int i = 16; i < 64; i++) {
            int s0 = rightrotate(message_schedule[i - 15], 7) ^ rightrotate(message_schedule[i - 15], 18) ^ (message_schedule[i - 15] >>> 3);
            int s1 = rightrotate(message_schedule[i - 2], 17) ^ rightrotate(message_schedule[i - 2], 19) ^ (message_schedule[i - 2] >>> 10);
            message_schedule[i] = message_schedule[i - 16] + s0 + message_schedule[i - 7] + s1;
        }
    }

    private void compress(){

        int a = h0;
        int b = h1;
        int c = h2;
        int d = h3;
        int e = h4;
        int f = h5;
        int g = h6;
        int h = h7;

        int S0;
        int S1;
        int ch;
        int maj;
        int tmp1;
        int tmp2;

        for (int i = 0; i < 64; i++) {
            S1 = rightrotate(e, 6) ^ rightrotate(e, 11) ^ rightrotate(e, 25);
            ch = (e & f) ^ ((~e) & g);
            tmp1 = h + S1 + ch + k[i] + message_schedule[i];

            S0 = rightrotate(a, 2) ^ rightrotate(a, 13) ^ rightrotate(a, 22);
            maj = (a & b) ^ (a & c) ^ (b & c);
            tmp2 = S0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + tmp1;
            d = c;
            c = b;
            b = a;
            a = tmp1 + tmp2;
        }

        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
        h5 += f;
        h6 += g;
        h7 += h;
    }

    private int rightrotate(int word, int n) {
        return word >>> n | ((word & ((1 << n) - 1)) << (32 - n));
    }

    public byte[] generate() {

        long L = Integer.toUnsignedLong(message_len << 3);
        message[message_offset++] = (byte) 0x80;

        if(message_offset > 56) {
            while (message_offset < 64) {
                message[message_offset++] = 0;
            }

            process_block(message);
            compress();
            message_offset = 0;
        }


        while (message_offset < 56) {
            message[message_offset++] = 0;
        }
        for (int i = 0; i < 8; i++) {
            message[56 + i] = (byte) (L >>> (56 - (i << 3)));
        }

        process_block(message);
        compress();

        byte[] hash = new byte[32];
        for (int i = 0; i < 4; i++) {
            hash[i] = (byte) ((h0 >> (24 - (i << 3))) & 0xFF);
            hash[4 + i] = (byte) ((h1 >> (24 - (i << 3))) & 0xFF);
            hash[8 + i] = (byte) ((h2 >> (24 - (i << 3))) & 0xFF);
            hash[12 + i] = (byte) ((h3 >> (24 - (i << 3))) & 0xFF);
            hash[16 + i] = (byte) ((h4 >> (24 - (i << 3))) & 0xFF);
            hash[20 + i] = (byte) ((h5 >> (24 - (i << 3))) & 0xFF);
            hash[24 + i] = (byte) ((h6 >> (24 - (i << 3))) & 0xFF);
            hash[28 + i] = (byte) ((h7 >> (24 - (i << 3))) & 0xFF);
        }

        reset();

        return hash;
    }

    public void reset() {
        h0 = h_init[0];
        h1 = h_init[1];
        h2 = h_init[2];
        h3 = h_init[3];
        h4 = h_init[4];
        h5 = h_init[5];
        h6 = h_init[6];
        h7 = h_init[7];
        message = new byte[64];
        message_len = 0;
        message_offset = 0;
        message_schedule = null;
    }
}
