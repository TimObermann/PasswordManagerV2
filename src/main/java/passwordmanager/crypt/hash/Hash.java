package passwordmanager.crypt.hash;

public interface Hash {
    void insert(byte[] message);
    byte[] generate();
    void reset();
    int getDigestSize();
    int getBlockSize();
    static byte[] hash(byte[] message, Hash algorithm) {
        algorithm.insert(message);
        return algorithm.generate();
    };
}
