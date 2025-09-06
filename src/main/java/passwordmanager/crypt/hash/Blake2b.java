package passwordmanager.crypt.hash;

import passwordmanager.crypt.mac.MAC;

public class Blake2b implements Hash, MAC {

    private final long[] iv = {
        0x6a09e667f3bcc908L, 0xbb67ae8584caa73bL, 0x3c6ef372fe94f82bL, 0xa54ff53a5f1d36f1L,
        0x510e527fade682d1L, 0x9b05688c2b3e6c1fL, 0x1f83d9abfb41bd6bL, 0x5be0cd19137e2179L
    };

    private final int[][] sigma = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0}
    };

    private final int R1 = 32;
    private final int R2 = 24;
    private final int R3 = 16;
    private final int R4 = 63;

    private int result_len;
    private long[] internal_state_h;
    private byte[] buffer;
    private long[] long_buffer;
    private int buffer_len;
    private long t0;
    private long t1;
    private boolean lazy_key_processed;
    private byte[] key;
    private final int BLOCK_SIZE = 128;

    public Blake2b(){
        init(null, 64);
    }

    public Blake2b(int nn) {
        init(null, nn);
    }

    public void init(byte[] key, int nn) {
        internal_state_h = new long[8];
        System.arraycopy(iv, 0, internal_state_h, 0, iv.length);

        byte kk = (byte) (key == null ? 0 : key.length);
        internal_state_h[0] ^= 0x01010000 ^ (kk << 8) ^ nn;

        buffer = new byte[128];
        long_buffer = new long[16];
        buffer_len = 0;
        t0 = 0;
        t1 = 0;
        result_len = nn;
        this.key = key;
        if(key == null) lazy_key_processed = true;
        else lazy_key_processed = false;
    }

    @Override
    public byte[] generateTag(byte[] message, byte[] key) {
        return Blake2b.hash(key, message, this.result_len);
    }

    private long rightrotate(long word, int n) {
        return word >>> n | ((word & ((1L << n) - 1)) << (64 - n));
    }

    private byte[] to_bytes(long[] h, int nn) {
        byte[] o = new byte[nn];
        byte long_index = 0;
        byte byte_index = 0;

        while (byte_index + 8 <= nn) {
            o[byte_index++] = (byte) ((h[long_index]) & 0xFF);
            o[byte_index++] = (byte) ((h[long_index] >> 8) & 0xFF);
            o[byte_index++] = (byte) ((h[long_index] >> 16) & 0xFF);
            o[byte_index++] = (byte) ((h[long_index] >> 24) & 0xFF);

            o[byte_index++] = (byte) ((h[long_index] >> 32) & 0xFF);
            o[byte_index++] = (byte) ((h[long_index] >> 40) & 0xFF);
            o[byte_index++] = (byte) ((h[long_index] >> 48) & 0xFF);
            o[byte_index++] = (byte) ((h[long_index] >> 56) & 0xFF);

            long_index++;
        }

        int s = 0;
        while (byte_index < nn) {
            o[byte_index++] = (byte) ((h[long_index] >> s) & 0xFF);

            s += 8;
        }

        return o;
    }

    private void G(long[] v, int a, int b, int c, int d, long x, long y){
        v[a] = (v[a] + v[b] + x);
        v[d] = rightrotate(v[d] ^v[a], R1);
        v[c] += v[d];
        v[b] = rightrotate(v[b] ^ v[c], R2);
        v[a] = (v[a] + v[b] + y);
        v[d] = rightrotate(v[d] ^ v[a], R3);
        v[c] += v[d];
        v[b] = rightrotate(v[b] ^ v[c], R4);
    }

    private void F(long[] h, long[] m, long t0, long t1,  boolean f) {
        long[] v = new long[16];
        System.arraycopy(h, 0, v, 0, h.length);
        System.arraycopy(iv, 0, v, h.length, iv.length);

        v[12] ^= t0;
        v[13] ^= t1;

        if(f) {
            v[14] ^= 0xFFFFFFFFFFFFFFFFL;
        }

        int[] s = new int[16];
        for (int i = 0; i < 12; i++) {
            System.arraycopy(sigma[i % 10], 0, s, 0, s.length);

            G(v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            G(v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            G(v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            G(v, 3, 7, 11, 15, m[s[6]], m[s[7]]);

            G(v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            G(v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            G(v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            G(v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }

        for (int i = 0; i < 8; i++) {
            h[i] ^= v[i] ^ v[i + 8];
        }
    }

    public void insert(byte[] message) {

        if(!lazy_key_processed && message.length != 0) {
            byte[] tmp = new byte[128];
            System.arraycopy(key, 0, tmp, 0, key.length);

            inPlaceBytesToLongs(tmp, long_buffer);
            t0 = 128;
            F(internal_state_h, long_buffer, t0, t1, false);

            lazy_key_processed = true;
        }

        int offset = 0;
        int message_len = message.length;


        if(buffer_len > 0) {

            int remaining_bytes = 128 - buffer_len;

            if(message_len < remaining_bytes) {
                System.arraycopy(message, 0, buffer, buffer_len, message_len);
                buffer_len += message_len;
                return;
            }

            System.arraycopy(message, 0, buffer, buffer_len, remaining_bytes);

            t0 += 128;
            if(t0 == 0) {
                t1 += 1;
            }

            inPlaceBytesToLongs(buffer, long_buffer);

            F(internal_state_h, long_buffer, t0, t1, false);

            offset += remaining_bytes;
            message_len -= remaining_bytes;
            buffer_len = 0;
        }

        while (message_len > 128) {
            t0 += 128;
            if(t0 == 0) t1 += 1;

            System.arraycopy(message, offset, buffer, buffer_len, 128);
            inPlaceBytesToLongs(buffer, long_buffer);

            F(internal_state_h, long_buffer, t0, t1, false);

            offset += 128;
            message_len -= 128;
        }

        if(message_len > 0) {
            buffer_len = message_len;
            System.arraycopy(message, offset, buffer, 0, message_len);
        }
    }

    public void reset() {
        t0 = 0;
        t1 = 0;
        buffer = new byte[128];
        buffer_len = 0;
        long_buffer = new long[16];
        System.arraycopy(iv, 0, internal_state_h, 0, iv.length);
        lazy_key_processed = false;
        key = new byte[0];
        result_len = 64;
    }

    public byte[] generate() {

        if(!lazy_key_processed) {
            byte[] tmp = new byte[128];
            System.arraycopy(key, 0, tmp, 0, key.length);
            inPlaceBytesToLongs(tmp, long_buffer);
            t0 = 128;
            F(internal_state_h, long_buffer, t0, t1, true);

            lazy_key_processed = true;

            byte[] out = to_bytes(internal_state_h, result_len);

            reset();

            return out;
        }


        t0 += buffer_len;

        for (int i = buffer_len; i < 128; i++) {
            buffer[i] = 0;
        }

        inPlaceBytesToLongs(buffer, long_buffer);

        F(internal_state_h, long_buffer, t0, t1, true);

        byte[] out = to_bytes(internal_state_h, result_len);

        reset();

        return out;
    }

    public byte[] generate_without_reset(int nn) {
        if(!lazy_key_processed) {
            if(key != null) {
                System.arraycopy(key, 0, buffer, 0, key.length);
                inPlaceBytesToLongs(buffer, long_buffer);
                t0 += 128;
                F(internal_state_h, long_buffer, t0, t1, false);
            }

            lazy_key_processed = true;
        }

        long local_t0 = t0 + buffer_len;
        long[] local_h = new long[8];
        byte[] local_buff = new byte[128];
        long[] local_long_buff = new long[16];

        System.arraycopy(internal_state_h, 0, local_h, 0, internal_state_h.length);
        System.arraycopy(buffer, 0, local_buff, 0, buffer_len);

        inPlaceBytesToLongs(local_buff, local_long_buff);

        F(local_h, local_long_buff, local_t0, t1, true);

        return to_bytes(internal_state_h, nn);
    }

    private void inPlaceBytesToLongs(byte[] b, long[] l) {
        for (int i = 0; i < l.length; i++) {
            l[i] = (b[i << 3] & 0xFF) | ((long) b[(i << 3) + 1] & 0xFF) << 8 | ((long) b[(i << 3) + 2] & 0xFF) << 16 | ((long) b[(i << 3) + 3] & 0xFF) << 24
                    | ((long) b[(i << 3) + 4] & 0xFF) << 32 | ((long) b[(i << 3) + 5] & 0xFF) << 40 | ((long) b[(i << 3) + 6] & 0xFF) << 48
                    | ((long) b[(i << 3) + 7] & 0xFF) << 56;
        }
    }

    public byte[] blake2b(long[][] d, long ll, byte kk, int nn) {
        long[] h = new long[8];
        System.arraycopy(iv, 0, h, 0, iv.length);

        h[0] ^= 0x01010000 ^ (kk << 8) ^ nn;

        if(d.length > 1) {
            for (int i = 0; i < d.length - 1; i++) {
                F(h, d[i], ((long) (i + 1) << 7L), 0L, false);
            }
        }

        if(kk == 0) {
            F(h, d[d.length - 1], ll, 0L,true);
        }
        else {
            F(h, d[d.length - 1], ll + 128L, 0L, true);
        }

        return to_bytes(h, nn);
    }

    private static long[] bytes_to_longs(byte[] b) {
        long[] l = new long[b.length / 8];

        for (int i = 0; i < l.length; i++) {
            l[i] = (b[i << 3] & 0xFF) | ((long) b[(i << 3) + 1] & 0xFF) << 8 | ((long) b[(i << 3) + 2] & 0xFF) << 16 | ((long) b[(i << 3) + 3] & 0xFF) << 24
                    | ((long) b[(i << 3) + 4] & 0xFF) << 32 | ((long) b[(i << 3) + 5] & 0xFF) << 40 | ((long) b[(i << 3) + 6] & 0xFF) << 48
                    | ((long) b[(i << 3) + 7] & 0xFF) << 56;
        }

        return l;
    }

    private void buildBlocks(byte[] message, byte[] buff, long[][] d, int curr) {
        byte[] tmp = buff;

        int currIndex = 0;
        for (int i = curr; i < d.length - 1; i++) {
            System.arraycopy(message, currIndex, tmp, 0, 128);
            d[i] = bytes_to_longs(tmp);

            currIndex += 128;
        }

        tmp = new byte[128];
        System.arraycopy(message, currIndex, tmp, 0, message.length - currIndex);
        d[d.length - 1] = bytes_to_longs(tmp);

    }

    private static byte[] hash(byte[] key, byte[] message, int nn) {
        Blake2b blake = new Blake2b();

        byte kk = (byte) (key == null ? 0 : key.length);

        if(message.length == 0 && kk == 0) {
            long[][] d = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
            return blake.blake2b(d, 0L, (byte) 0, nn);
        }

        int dd = (kk > 0 ? 1 : 0) + (message.length > 0 ? (message.length + 127) / 128 : 0);


        long[][] d = new long[dd][16];
        byte[] buff = new byte[128];
        int curr = 0;

        if(kk > 0) {
            System.arraycopy(key, 0, buff, 0, key.length);
            d[curr++] = bytes_to_longs(buff);
        }

        if(message.length > 0){
            blake.buildBlocks(message, buff, d, curr);
        }

        return blake.blake2b(d, message.length, kk, nn);
    }

    @Override
    public int getDigestSize() {
        return result_len;
    }

    @Override
    public int getBlockSize() {
        return BLOCK_SIZE;
    }
}
