package passwordmanager.crypt.mac;

import passwordmanager.crypt.hash.Hash;

public class HMAC implements MAC{

    private final Hash hashingAlgorithm;

    public HMAC(Hash hashingAlgorithm) {
        this.hashingAlgorithm = hashingAlgorithm;
    }

    private byte[] pad_key(byte[] key, int block_size) {

        byte[] padded_key = new byte[block_size];

        if(key.length > block_size) {
            key = Hash.hash(key, hashingAlgorithm);
            System.arraycopy(key, 0, padded_key, 0, key.length);
        }
        else if (key.length < block_size) {
            System.arraycopy(key, 0, padded_key, 0, key.length);
        }
        else {
            return key;
        }

        return padded_key;
    }


    private byte[] generate(byte[] message, byte[] key, int block_size) {
        byte[] padded_key = pad_key(key, block_size);

        byte[] inner_key = new byte[padded_key.length];
        byte[] outer_key = new byte[padded_key.length];

        for (int i = 0; i < padded_key.length; i++) {
            inner_key[i] = (byte) (padded_key[i] ^ 0x36);
            outer_key[i] = (byte) (padded_key[i] ^ 0x5c);
        }

        hashingAlgorithm.insert(inner_key);
        hashingAlgorithm.insert(message);

        byte[] first_hash = hashingAlgorithm.generate();

        hashingAlgorithm.insert(outer_key);
        hashingAlgorithm.insert(first_hash);

        return hashingAlgorithm.generate();
    }

    @Override
    public byte[] generateTag(byte[] message, byte[] key) {
        return generate(message, key, hashingAlgorithm.getBlockSize());
    }

    public boolean verify(byte[] message, byte[] key, byte[] storedTag) {
        byte[] attemptedTag = generateTag(message, key);

        int d = 0;
        for (int i = 0; i < storedTag.length; i++) {
            d |= storedTag[i] ^ attemptedTag[i];
        }

        return d == 0;
    }

    public Hash getHashingAlgorithm() {
        return hashingAlgorithm;
    }
}
