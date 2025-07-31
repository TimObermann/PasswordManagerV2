package passwordmanager.api.Fortuna;

import passwordmanager.api.SHA2.SHA2;


public class Fortuna {
    private SHA2 hash;
    private AES block_cipher;

    private byte[] key;
    private int ctr;

    public Fortuna() {
        byte[] seed = generateIV();
        ctr = 0;
        hash = new SHA2();

        byte[] IV = new byte[seed.length / 2];
        System.arraycopy(seed, 0, IV, 0, IV.length);
        block_cipher = new AES(IV);

    }

    public void reseed() {
        hash.insert(key);
        hash.insert(int_to_byte_array(ctr));
        key = hash.generate();
        ctr++;
    }

    private byte[] generateBlocks(int k) {
        if(ctr != 0){
            byte[] r = new byte[k << 4];

            for (int i = 0; i < k; i++) {
                System.arraycopy(block_cipher.encrypt(int_to_byte_array(ctr), bytes_to_ints(key)), 0 , r, i << 4,16);
                ctr++;
            }
            return r;
        }
        return null;
    }

    private int[] bytes_to_ints (byte[] bytes) {
        int[] o = new int[bytes.length / 4];
        for (int i = 0; i < o.length; i++) {
            o[i] = ((bytes[i] >> 24) & 0xFF) | ((bytes[i + 1] >> 16) & 0xFF) | ((bytes[i + 2] >> 8) & 0xFF) | ((bytes[i + 3]) & 0xFF);
        }
        return o;
    }

    private byte[] long_to_byte_array(long l){
        return new byte[]{
                (byte) ((l >> 56) & 0xFF),
                (byte) ((l >> 48) & 0xFF),
                (byte) ((l >> 40) & 0xFF),
                (byte) ((l >> 32) & 0xFF),
                (byte) ((l >> 24) & 0xFF),
                (byte) ((l >> 16) & 0xFF),
                (byte) ((l >> 8) & 0xFF),
                (byte) ((l) & 0xFF)
        };
    }
    private byte[] int_to_byte_array(int l){
        return new byte[]{
                (byte) ((l >> 24) & 0xFF),
                (byte) ((l >> 16) & 0xFF),
                (byte) ((l >> 8) & 0xFF),
                (byte) ((l) & 0xFF)
        };
    }

    public byte[] generateIV(){

        SHA2 hash = new SHA2();

        hash.insert(long_to_byte_array(System.nanoTime()));
        hash.insert(long_to_byte_array(Runtime.getRuntime().freeMemory()));

        for (int i = 0; i < 1000; i++) {
            hash.insert(int_to_byte_array(System.identityHashCode(new Object())));

            if((i & 7) == 0) {
                hash.insert(long_to_byte_array(System.nanoTime()));
            }

            if((i & 15) == 0) {
                hash.insert(long_to_byte_array(Runtime.getRuntime().freeMemory()));
            }
        }

        hash.insert(long_to_byte_array(Runtime.getRuntime().maxMemory()));
        hash.insert(int_to_byte_array(Thread.getAllStackTraces().size()));

        return hash.generate();
    }

    public int generateInt(){
        return 0;
    }

    public long generateLong(){
        return 0L;
    }

    public byte[] generateBytes_12() {
        return new byte[0];
    }
    public byte[] generateBytes_16() {
        return new byte[0];
    }

}
