package passwordmanager.crypt.cipher.chacha;

import passwordmanager.crypt.mac.Poly1305;
import passwordmanager.gui.AuthenticityViolationError;

public class ChaCha20_Poly1305 {
    private ChaCha chaCha;
    private Poly1305 poly1305;

    public ChaCha20_Poly1305() {
        this.chaCha = new ChaCha(20);
        this.poly1305 = new Poly1305();
    }

    public ChaCha20_Poly1305(int parallelization) {
        this.chaCha = new ChaCha(20, parallelization);
        this.poly1305 = new Poly1305();
    }

    private byte[] key_gen(int[] key, int[] nonce) {
        byte[] block = new byte[64];
        byte[] out = new byte[32];

        chaCha.chacha_block(key, 0, nonce, block);

        System.arraycopy(block, 0, out, 0, 32);

        return out;
    }

    private byte[] calculateAuthTag(byte[] otk, byte[] aad, byte[] ciphertext) {
        int padding1 = (16 - (aad.length & 15)) & 15;
        int padding2 = (16 - (ciphertext.length) & 15) & 15;

        byte[] tagMessage = new byte[aad.length + padding1 + ciphertext.length + padding2 + 16];
        System.arraycopy(aad, 0, tagMessage, 0, aad.length);
        System.arraycopy(ciphertext, 0, tagMessage, aad.length + padding1, ciphertext.length);

        System.arraycopy(long_to_bytes(aad.length), 0, tagMessage, aad.length + padding1 + ciphertext.length + padding2, 8);
        System.arraycopy(long_to_bytes(ciphertext.length), 0, tagMessage, aad.length + padding1 + ciphertext.length + padding2 + 8, 8);

        return poly1305.poly1305_mac(tagMessage, otk);
    }

    public byte[] encrypt(byte[] plaintext, int[] key, byte[] IV, int session_constant, byte[] aad) {

        int[] nonce = new int[3];
        nonce[0] = session_constant;
        System.arraycopy(bytes_to_ints(IV, 2), 0, nonce, 1, 2);

        byte[] one_time_key = key_gen(key, nonce);
        byte[] ciphertext = chaCha.chacha_encrypt(plaintext, key,1, nonce);

        byte[] authTag = calculateAuthTag(one_time_key, aad, ciphertext);

        byte[] out = new byte[authTag.length + ciphertext.length];

        System.arraycopy(ciphertext, 0, out, 0, ciphertext.length);
        System.arraycopy(authTag, 0, out, ciphertext.length, authTag.length);

        return out;
    }

    protected byte[] encrypt(byte[] plaintext, int[] key, int[] nonce, byte[] aad) {

        byte[] one_time_key = key_gen(key, nonce);
        byte[] ciphertext = chaCha.chacha_encrypt(plaintext, key,1, nonce);

        byte[] authTag = calculateAuthTag(one_time_key, aad, ciphertext);

        byte[] out = new byte[authTag.length + ciphertext.length];

        System.arraycopy(ciphertext, 0, out, 0, ciphertext.length);
        System.arraycopy(authTag, 0, out, ciphertext.length, authTag.length);

        return out;
    }

    public byte[] decrypt(byte[] secret_data, int[] key, byte[] IV, int session_constant, byte[] aad) {
        byte[] authTag = new byte[16];
        byte[] ciphertext = new byte[secret_data.length - 16];

        System.arraycopy(secret_data, 0, ciphertext, 0, ciphertext.length);
        System.arraycopy(secret_data, ciphertext.length, authTag, 0, 16);

        int[] nonce = new int[3];
        nonce[0] = session_constant;
        System.arraycopy(bytes_to_ints(IV, 2), 0, nonce, 1, 2);

        byte[] one_time_key = key_gen(key, nonce);
        byte[] checkTag = calculateAuthTag(one_time_key, aad, ciphertext);

        if(!compareTags(authTag, checkTag)){
            throw new AuthenticityViolationError();
        }

        return chaCha.chacha_encrypt(ciphertext, key, 1, nonce);
    }

    public byte[] decrypt(byte[] secret_data, int[] key, int[] nonce, byte[] aad) {
        byte[] authTag = new byte[16];
        byte[] ciphertext = new byte[secret_data.length - 16];

        System.arraycopy(secret_data, 0, ciphertext, 0, ciphertext.length);
        System.arraycopy(secret_data, ciphertext.length, authTag, 0, 16);

        byte[] one_time_key = key_gen(key, nonce);
        byte[] checkTag = calculateAuthTag(one_time_key, aad, ciphertext);

        if(!compareTags(authTag, checkTag)){
            throw new AuthenticityViolationError();
        }

        return chaCha.chacha_encrypt(ciphertext, key, 1, nonce);
    }

    private boolean compareTags(byte[] trueTag, byte[] actualTag) {
        int diff = 0;

        for (int i = 0; i < actualTag.length; i++) {
            diff |= actualTag[i] ^ trueTag[i];
        }

        return diff == 0;
    }

    private byte[] long_to_bytes(long l) {
        return new byte[] {(byte) (l & 0xFF), (byte) ((l >> 8) & 0xFF), (byte) ((l >> 16) & 0xFF), (byte) ((l >> 24) & 0xFF), (byte) ((l >> 32) & 0xFF), (byte) ((l >> 40) & 0xFF), (byte) ((l >> 48) & 0xFF), (byte) ((l >> 56) & 0xFF)};
    }

    private int[] bytes_to_ints(byte[] b, int len) {
        int[] l = new int[len];

        for (int i = 0; i < l.length; i++) {
            l[i] = (b[i << 2] & 0xFF) | ((int) b[(i << 2) + 1] & 0xFF) << 8 | ((int) b[(i << 2) + 2] & 0xFF) << 16 | ((int) b[(i << 2) + 3] & 0xFF) << 24;
        }

        return l;
    }

}
