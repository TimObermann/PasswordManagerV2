package passwordmanager.crypt.mac;

import passwordmanager.crypt.hash.SHA2;

public class HMAC {

    private final SHA2 hashingAlgorithm;

    public HMAC(SHA2 hashingAlgorithm) {
        this.hashingAlgorithm = hashingAlgorithm;
    }

    private byte[] pad_key(byte[] key, int block_size) {

        byte[] padded_key = new byte[block_size];

        if(key.length > block_size) {
            key = SHA2.hash(key);
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


    public byte[] generate(byte[] message, byte[] key, int block_size) {
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
}
