package passwordmanager.crypt.mac;

import java.math.BigInteger;

public class Poly1305 implements MAC {

    private BigInteger clamp(BigInteger r) {
        return r.and(new BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16));
    }

    private byte[] reverse(byte[] a, int offset, int len) {
        byte[] inv = new byte[len];

        int index = len - 1;

        for (int i = 0; i < len; i++) {
            inv[index--] = a[i + offset];
        }

        return inv;
    }

    private byte[] poly1305_mac(byte[] message, byte[] key) {

        BigInteger p = new BigInteger("3fffffffffffffffffffffffffffffffb", 16);

        BigInteger r = new BigInteger(1, reverse(key, 0, 16));
        r = clamp(r);

        BigInteger s = new BigInteger(1, reverse(key, 16, 16));
        BigInteger acc = BigInteger.ZERO;

        int offset = 0;
        for (int i = 0; i < Math.ceilDiv(message.length, 16); i++) {
            int size = Math.min(16, message.length - offset);
            byte[] n = new byte[17];

            System.arraycopy(message, offset, n, 0, size);
            n[size] = (byte) 0x01;

            BigInteger block = new BigInteger(1, reverse(n, 0, 17));

            acc = acc.add(block);
            acc = (r.multiply(acc)).mod(p);

            offset += 16;
        }
        acc = acc.add(s);

        return to_little_endian_bytes(acc, 16);
    }

    private byte[] to_little_endian_bytes(BigInteger b, int len) {
        byte[] big_endian = b.toByteArray();
        byte[] little_endian = new byte[len];

        for (int i = 0; i < len; i++) {
            int index = big_endian.length - 1 - i;

            if(index >= 0){
                little_endian[i] = big_endian[index];
            }
        }

        return little_endian;
    }

    @Override
    public byte[] generateTag(byte[] message, byte[] key) {
        return poly1305_mac(message, key);
    }
}
