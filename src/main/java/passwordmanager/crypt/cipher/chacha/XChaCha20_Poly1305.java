package passwordmanager.crypt.cipher.chacha;

public class XChaCha20_Poly1305 {

    private final XChaCha chaCha;
    private final ChaCha20_Poly1305 chaChaPoly;

    public XChaCha20_Poly1305() {
        chaCha = new XChaCha(20);
        chaChaPoly = new ChaCha20_Poly1305();
    }

    public XChaCha20_Poly1305(int parallelization) {
        chaCha = new XChaCha(20, parallelization);
        chaChaPoly = new ChaCha20_Poly1305();
    }

    public byte[] encrypt(byte[] plaintext, int[] key, int[] nonce, byte[] aad) {

        int[] true_nonce = new int[3];
        int[] smallNonce = new int[4];

        System.arraycopy(nonce, 0, smallNonce, 0, 4);
        System.arraycopy(nonce, 4, true_nonce, 1, 2);

        int[] subkey = chaCha.HChaCha(key, smallNonce);

        return chaChaPoly.encrypt(plaintext, subkey, true_nonce, aad);
    }

    public byte[] decrypt(byte[] secret_data, int[] key, int[] nonce, byte[] aad) {
        int[] true_nonce = new int[3];
        int[] smallNonce = new int[4];

        System.arraycopy(nonce, 0, smallNonce, 0, 4);
        System.arraycopy(nonce, 4, true_nonce, 1, 2);

        int[] subkey = chaCha.HChaCha(key, smallNonce);

        return chaChaPoly.decrypt(secret_data, subkey, true_nonce, aad);
    }
}
