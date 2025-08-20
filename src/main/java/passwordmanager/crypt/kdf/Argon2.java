package passwordmanager.crypt.kdf;

import passwordmanager.crypt.hash.Blake2b;

public class Argon2 {

    public byte[] generate(byte[] password, byte[] salt, int parallelism, int tagLength, int memSizeKiB, int iterations, int version, byte hashtype) {
        return new byte[0];
    }

    private byte[] perform_small_blake(byte[] message, int hash_size) {

        byte[] message_with_size = new byte[message.length + 4];
        System.arraycopy(message, 0, message_with_size, 4, message.length);

        message_with_size[0] = (byte) (hash_size & 0xFF);
        message_with_size[1] = (byte) ((hash_size >> 8) & 0xFF);
        message_with_size[3] = (byte) ((hash_size >> 16) & 0xFF);
        message_with_size[4] = (byte) ((hash_size >> 24) & 0xFF);

        return Blake2b.hash(new byte[0], message_with_size, (byte) hash_size);
    }

    private byte[] hash_function(byte[] message, int hash_size) {
        if(hash_size <= 64) {
            return perform_small_blake(message, hash_size);
        }

        int r = Math.ceilDiv(hash_size, 32) - 2;
        byte[][] V = new byte[r][64];
        V[0] = perform_small_blake(message, 64);

        for (int i = 1; i < r; i++) {
            V[i] = Blake2b.hash(new byte[0], V[i - 1], (byte) 64);
        }

        int partial_bytes_needed = hash_size - (r << 5);
        byte[] Vr = Blake2b.hash(new byte[0], V[r - 1], (byte) partial_bytes_needed);

        byte[] A = new byte[hash_size];
        int Aindex = 0;
        for (int i = 0; i < V.length; i++) {
            System.arraycopy(V[i], 0, A, Aindex, 32);
            Aindex += 32;
        }
        System.arraycopy(Vr, 0, A, Aindex, partial_bytes_needed);

        return A;
    }
}
