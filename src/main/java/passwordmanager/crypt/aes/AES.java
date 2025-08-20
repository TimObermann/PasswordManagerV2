package passwordmanager.crypt.aes;

import java.security.SecureRandom;

public class AES {

    //https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=901427

    //AES constants
    //Nb, amount of columns in state
    //Nk, number of words in key
    //Nr, number of rounds
    private final byte Nb;
    private final byte Nk;
    private final byte Nr;

    //Available key sizes are 128, 192, 256
    //Modes are
    // -ECM (NEVER USE THIS)
    // -CBC (with a random nonce)
    // -CTR
    public final AES_SIZE size;
    public final AES_MODE mode;

    //used to create random nonce
    private final SecureRandom rng = new SecureRandom();



    //lookup-tables for the cipher.
    //In an environment where absolute security is a must,
    //this could be exploited with a timing attack
    private final byte[][] SBox = {
            {(byte)0x63, (byte)0x7c, (byte)0x77, (byte)0x7b, (byte)0xf2, (byte)0x6b, (byte)0x6f, (byte)0xc5, (byte)0x30, (byte)0x01, (byte)0x67, (byte)0x2b, (byte)0xfe, (byte)0xd7, (byte)0xab, (byte)0x76},
            {(byte)0xca, (byte)0x82, (byte)0xc9, (byte)0x7d, (byte)0xfa, (byte)0x59, (byte)0x47, (byte)0xf0, (byte)0xad, (byte)0xd4, (byte)0xa2, (byte)0xaf, (byte)0x9c, (byte)0xa4, (byte)0x72, (byte)0xc0},
            {(byte)0xb7, (byte)0xfd, (byte)0x93, (byte)0x26, (byte)0x36, (byte)0x3f, (byte)0xf7, (byte)0xcc, (byte)0x34, (byte)0xa5, (byte)0xe5, (byte)0xf1, (byte)0x71, (byte)0xd8, (byte)0x31, (byte)0x15},
            {(byte)0x04, (byte)0xc7, (byte)0x23, (byte)0xc3, (byte)0x18, (byte)0x96, (byte)0x05, (byte)0x9a, (byte)0x07, (byte)0x12, (byte)0x80, (byte)0xe2, (byte)0xeb, (byte)0x27, (byte)0xb2, (byte)0x75},
            {(byte)0x09, (byte)0x83, (byte)0x2c, (byte)0x1a, (byte)0x1b, (byte)0x6e, (byte)0x5a, (byte)0xa0, (byte)0x52, (byte)0x3b, (byte)0xd6, (byte)0xb3, (byte)0x29, (byte)0xe3, (byte)0x2f, (byte)0x84},
            {(byte)0x53, (byte)0xd1, (byte)0x00, (byte)0xed, (byte)0x20, (byte)0xfc, (byte)0xb1, (byte)0x5b, (byte)0x6a, (byte)0xcb, (byte)0xbe, (byte)0x39, (byte)0x4a, (byte)0x4c, (byte)0x58, (byte)0xcf},
            {(byte)0xd0, (byte)0xef, (byte)0xaa, (byte)0xfb, (byte)0x43, (byte)0x4d, (byte)0x33, (byte)0x85, (byte)0x45, (byte)0xf9, (byte)0x02, (byte)0x7f, (byte)0x50, (byte)0x3c, (byte)0x9f, (byte)0xa8},
            {(byte)0x51, (byte)0xa3, (byte)0x40, (byte)0x8f, (byte)0x92, (byte)0x9d, (byte)0x38, (byte)0xf5, (byte)0xbc, (byte)0xb6, (byte)0xda, (byte)0x21, (byte)0x10, (byte)0xff, (byte)0xf3, (byte)0xd2},
            {(byte)0xcd, (byte)0x0c, (byte)0x13, (byte)0xec, (byte)0x5f, (byte)0x97, (byte)0x44, (byte)0x17, (byte)0xc4, (byte)0xa7, (byte)0x7e, (byte)0x3d, (byte)0x64, (byte)0x5d, (byte)0x19, (byte)0x73},
            {(byte)0x60, (byte)0x81, (byte)0x4f, (byte)0xdc, (byte)0x22, (byte)0x2a, (byte)0x90, (byte)0x88, (byte)0x46, (byte)0xee, (byte)0xb8, (byte)0x14, (byte)0xde, (byte)0x5e, (byte)0x0b, (byte)0xdb},
            {(byte)0xe0, (byte)0x32, (byte)0x3a, (byte)0x0a, (byte)0x49, (byte)0x06, (byte)0x24, (byte)0x5c, (byte)0xc2, (byte)0xd3, (byte)0xac, (byte)0x62, (byte)0x91, (byte)0x95, (byte)0xe4, (byte)0x79},
            {(byte)0xe7, (byte)0xc8, (byte)0x37, (byte)0x6d, (byte)0x8d, (byte)0xd5, (byte)0x4e, (byte)0xa9, (byte)0x6c, (byte)0x56, (byte)0xf4, (byte)0xea, (byte)0x65, (byte)0x7a, (byte)0xae, (byte)0x08},
            {(byte)0xba, (byte)0x78, (byte)0x25, (byte)0x2e, (byte)0x1c, (byte)0xa6, (byte)0xb4, (byte)0xc6, (byte)0xe8, (byte)0xdd, (byte)0x74, (byte)0x1f, (byte)0x4b, (byte)0xbd, (byte)0x8b, (byte)0x8a},
            {(byte)0x70, (byte)0x3e, (byte)0xb5, (byte)0x66, (byte)0x48, (byte)0x03, (byte)0xf6, (byte)0x0e, (byte)0x61, (byte)0x35, (byte)0x57, (byte)0xb9, (byte)0x86, (byte)0xc1, (byte)0x1d, (byte)0x9e},
            {(byte)0xe1, (byte)0xf8, (byte)0x98, (byte)0x11, (byte)0x69, (byte)0xd9, (byte)0x8e, (byte)0x94, (byte)0x9b, (byte)0x1e, (byte)0x87, (byte)0xe9, (byte)0xce, (byte)0x55, (byte)0x28, (byte)0xdf},
            {(byte)0x8c, (byte)0xa1, (byte)0x89, (byte)0x0d, (byte)0xbf, (byte)0xe6, (byte)0x42, (byte)0x68, (byte)0x41, (byte)0x99, (byte)0x2d, (byte)0x0f, (byte)0xb0, (byte)0x54, (byte)0xbb, (byte)0x16}
    };

    private final byte[][] InvSBox = {
            {(byte)0x52, (byte)0x09, (byte)0x6a, (byte)0xd5, (byte)0x30, (byte)0x36, (byte)0xa5, (byte)0x38, (byte)0xbf, (byte)0x40, (byte)0xa3, (byte)0x9e, (byte)0x81, (byte)0xf3, (byte)0xd7, (byte)0xfb},
            {(byte)0x7c, (byte)0xe3, (byte)0x39, (byte)0x82, (byte)0x9b, (byte)0x2f, (byte)0xff, (byte)0x87, (byte)0x34, (byte)0x8e, (byte)0x43, (byte)0x44, (byte)0xc4, (byte)0xde, (byte)0xe9, (byte)0xcb},
            {(byte)0x54, (byte)0x7b, (byte)0x94, (byte)0x32, (byte)0xa6, (byte)0xc2, (byte)0x23, (byte)0x3d, (byte)0xee, (byte)0x4c, (byte)0x95, (byte)0x0b, (byte)0x42, (byte)0xfa, (byte)0xc3, (byte)0x4e},
            {(byte)0x08, (byte)0x2e, (byte)0xa1, (byte)0x66, (byte)0x28, (byte)0xd9, (byte)0x24, (byte)0xb2, (byte)0x76, (byte)0x5b, (byte)0xa2, (byte)0x49, (byte)0x6d, (byte)0x8b, (byte)0xd1, (byte)0x25},
            {(byte)0x72, (byte)0xf8, (byte)0xf6, (byte)0x64, (byte)0x86, (byte)0x68, (byte)0x98, (byte)0x16, (byte)0xd4, (byte)0xa4, (byte)0x5c, (byte)0xcc, (byte)0x5d, (byte)0x65, (byte)0xb6, (byte)0x92},
            {(byte)0x6c, (byte)0x70, (byte)0x48, (byte)0x50, (byte)0xfd, (byte)0xed, (byte)0xb9, (byte)0xda, (byte)0x5e, (byte)0x15, (byte)0x46, (byte)0x57, (byte)0xa7, (byte)0x8d, (byte)0x9d, (byte)0x84},
            {(byte)0x90, (byte)0xd8, (byte)0xab, (byte)0x00, (byte)0x8c, (byte)0xbc, (byte)0xd3, (byte)0x0a, (byte)0xf7, (byte)0xe4, (byte)0x58, (byte)0x05, (byte)0xb8, (byte)0xb3, (byte)0x45, (byte)0x06},
            {(byte)0xd0, (byte)0x2c, (byte)0x1e, (byte)0x8f, (byte)0xca, (byte)0x3f, (byte)0x0f, (byte)0x02, (byte)0xc1, (byte)0xaf, (byte)0xbd, (byte)0x03, (byte)0x01, (byte)0x13, (byte)0x8a, (byte)0x6b},
            {(byte)0x3a, (byte)0x91, (byte)0x11, (byte)0x41, (byte)0x4f, (byte)0x67, (byte)0xdc, (byte)0xea, (byte)0x97, (byte)0xf2, (byte)0xcf, (byte)0xce, (byte)0xf0, (byte)0xb4, (byte)0xe6, (byte)0x73},
            {(byte)0x96, (byte)0xac, (byte)0x74, (byte)0x22, (byte)0xe7, (byte)0xad, (byte)0x35, (byte)0x85, (byte)0xe2, (byte)0xf9, (byte)0x37, (byte)0xe8, (byte)0x1c, (byte)0x75, (byte)0xdf, (byte)0x6e},
            {(byte)0x47, (byte)0xf1, (byte)0x1a, (byte)0x71, (byte)0x1d, (byte)0x29, (byte)0xc5, (byte)0x89, (byte)0x6f, (byte)0xb7, (byte)0x62, (byte)0x0e, (byte)0xaa, (byte)0x18, (byte)0xbe, (byte)0x1b},
            {(byte)0xfc, (byte)0x56, (byte)0x3e, (byte)0x4b, (byte)0xc6, (byte)0xd2, (byte)0x79, (byte)0x20, (byte)0x9a, (byte)0xdb, (byte)0xc0, (byte)0xfe, (byte)0x78, (byte)0xcd, (byte)0x5a, (byte)0xf4},
            {(byte)0x1f, (byte)0xdd, (byte)0xa8, (byte)0x33, (byte)0x88, (byte)0x07, (byte)0xc7, (byte)0x31, (byte)0xb1, (byte)0x12, (byte)0x10, (byte)0x59, (byte)0x27, (byte)0x80, (byte)0xec, (byte)0x5f},
            {(byte)0x60, (byte)0x51, (byte)0x7f, (byte)0xa9, (byte)0x19, (byte)0xb5, (byte)0x4a, (byte)0x0d, (byte)0x2d, (byte)0xe5, (byte)0x7a, (byte)0x9f, (byte)0x93, (byte)0xc9, (byte)0x9c, (byte)0xef},
            {(byte)0xa0, (byte)0xe0, (byte)0x3b, (byte)0x4d, (byte)0xae, (byte)0x2a, (byte)0xf5, (byte)0xb0, (byte)0xc8, (byte)0xeb, (byte)0xbb, (byte)0x3c, (byte)0x83, (byte)0x53, (byte)0x99, (byte)0x61},
            {(byte)0x17, (byte)0x2b, (byte)0x04, (byte)0x7e, (byte)0xba, (byte)0x77, (byte)0xd6, (byte)0x26, (byte)0xe1, (byte)0x69, (byte)0x14, (byte)0x63, (byte)0x55, (byte)0x21, (byte)0x0c, (byte)0x7d}
    };


    //these are matrices
    private final byte[][] a = {
            {0x02, 0x03, 0x01, 0x01},
            {0x01, 0x02, 0x03, 0x01},
            {0x01, 0x01, 0x02, 0x03},
            {0x03, 0x01, 0x01, 0x02}
    };

    private final byte[][] inv_a = {
            {(byte)0x0e, (byte)0x0b, (byte)0x0d, (byte)0x09},
            {(byte)0x09, (byte)0x0e, (byte)0x0b, (byte)0x0d},
            {(byte)0x0d, (byte)0x09, (byte)0x0e, (byte)0x0b},
            {(byte)0x0b, (byte)0x0d, (byte)0x09, (byte)0x0e}
    };

    //Set of values used in key expansion
    //they're always doubled within GF(2^8)
    private final int[] Rcon = {
            0x01,
            0x02,
            0x04,
            0x08,
            0x10,
            0x20,
            0x40,
            0x80,
            0x1B,
            0x36,
            0x6C,
            0xD8,
            0xAB,
            0x4D
    };



    public AES(AES_SIZE size, AES_MODE mode){
        this.size = size;
        this.mode = mode;

        //set the constants for each key size
        switch (size) {
            case AES_128 -> {
                this.Nk = 4;
                this.Nb = 4;
                this.Nr = 10;
            }
            case AES_192 -> {
                this.Nk = 6;
                this.Nb = 4;
                this.Nr = 12;
            }
            case AES_256 -> {
                this.Nk = 8;
                this.Nb = 4;
                this.Nr = 14;
            }
            default -> throw new IllegalStateException("How did you do that?!");
        }
    }

    public AES(AES_SIZE size) {
        this(size, AES_MODE.CBC);
    }

    public AES(){
        this(AES_SIZE.AES_256, AES_MODE.CBC);
    }

    //this is the actual AES encryption method
    //takes a 16 byte block and the expanded key schedule
    //and returns the state after the AES algorithm was applied to the input
    private byte[][] c(byte[] in, int[] key_schedule){

        //build the state
        byte[][] state = new byte[4][Nb];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = in[i + (j << 2)];
            }
        }

        //start the encryption
        AddRoundKey(state, array_copy_of_range(key_schedule, 0, Nb));

        for (int round = 1; round < Nr; round++) {
            SubBytes(state);
            ShiftRows(state);
            MixColumns(state);
            AddRoundKey(state, array_copy_of_range(key_schedule, round * Nb, (round+1) * Nb));
        }

        SubBytes(state);
        ShiftRows(state);
        AddRoundKey(state, array_copy_of_range(key_schedule, Nr*Nb, (Nr+1) * Nb));

        return state;
    }

    //this method adds a part of the expanded key column wise to the state
    //Note addition is performed through the xor operation within the galois finite field
    private void AddRoundKey(byte[][] state, int[] key_schedule){
        for (int i = 0; i < 4; i++) {
            state[3][i] = (byte) (state[3][i] ^ (key_schedule[i] & 0xFF));
            state[2][i] = (byte) (state[2][i] ^ ((key_schedule[i] >> 8) & 0xFF));
            state[1][i] = (byte) (state[1][i] ^ ((key_schedule[i] >> 16) & 0xFF));
            state[0][i] = (byte) (state[0][i] ^ ((key_schedule[i] >> 24) & 0xFF));
        }
    }

    //substitutes each byte within the state through the SBox lookup table
    //the byte 0x53 will be substituted with the byte at row = 3, column = 5 in the SBox
    private void SubBytes(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = SBox[((state[i][j] & 0xFF) >> 4) & 0xF][(state[i][j] & 0xFF) & 0xF];
            }
        }
    }

    //this shifts the rows of the state by their index
    //so row 0 is shifted by 0, row 1 shifted by 1 etc.
    //the shift is left.
    /*
        0 1 2 3      0 1 2 3
        0 1 2 3  ->  1 2 3 0
        0 1 2 3      2 3 0 1
        0 1 2 3      3 0 1 2
     */
    private void ShiftRows(byte[][] state) {

        byte[][] tmp = new byte[4][4];
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 4; i++) {
                tmp[j][i] = state[j][(i + j) % 4];
            }
        }

        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 4; i++) {
                state[j][i] = tmp[j][i];
            }
        }
    }


    //multiplication within the galois finite field
    //this uses a variation of the russian peasants algorithm
    private byte gmul(byte a, byte b){
        byte p = 0;

        for (int i = 0; i < 8; i++) {
            if((b & 1) == 1) {
                p ^= a;
            }

            boolean carry = ((0x80 & a) != 0);
            b >>= 1;
            a = (byte) ((a << 1) & 0xFF);

            if(carry) {
                a ^= 0x1b;
            }
        }

        return p;
    }

    //a helper for the matrix multiplication in MixColumns
    private byte rowTimesCol(byte[] row, byte[] col){
        byte o = 0;

        for (int i = 0; i < 4; i++) {
            o ^= gmul(row[i], col[i]);
        }

        return o;
    }

    // we perform a matrix multiplication with a
    // c' = a * c
    private void MixColumns(byte[][] state) {
        byte[][] tmp = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            byte[] column = new byte[4];
            for (int j = 0; j < 4; j++) {
                column[j] = state[j][i];
            }

            for (int j = 0; j < 4; j++) {
                tmp[j][i] = rowTimesCol(a[j], column);
            }
        }

        for (int j = 0; j < 4; j++) {
            System.arraycopy(tmp[j], 0, state[j], 0, 4);
        }
    }

    //this is the key expansion it enhances the quality of the key
    //and transforms it suit the needs of the algorithm
    private int[] key_expansion(byte[] key){
        int tmp;

        int[] w = new int[Nb * (Nr + 1)];

        //the key is concatenated into the first Nk words of w
        for (int i = 0; i < Nk; i++) {
            w[i] = (key[(i << 2) + 3] & 0xFF) | ((key[(i << 2) + 2] & 0xFF) << 8) | ((key[(i << 2) + 1] & 0xFF) << 16) | ((key[(i << 2)] & 0xFF) << 24);
        }

        //the rest of the words in the expanded key schedul w
        //are calculated based on the first Nk words
        for (int i = Nk; i < (Nb * (Nr + 1)); i++) {
            tmp = w[i - 1];

            if(i % Nk == 0){
                tmp = SubWord(RotWord(tmp)) ^ (Rcon[(i / Nk) - 1] << 24);
            }
            else if(Nk > 6 && (i % Nk == 4)) {
                tmp = SubWord(tmp);
            }

            w[i] = w[i - Nk] ^ tmp;
        }

        return w;
    }

    //this substitues the 4 bytes a the word with corresponding bytes from the SBox
    private int SubWord(int word) {
        int b0 = SBox[((word >> 24) & 0xFF) >> 4][(word >> 24) & 0xF] & 0xFF;
        int b1 = SBox[((word >> 16) & 0xFF) >> 4][(word >> 16) & 0xF] & 0xFF;
        int b2 = SBox[((word >> 8) & 0xFF) >> 4][(word >> 8) & 0xF] & 0xFF;
        int b3 = SBox[(word & 0xFF) >> 4][word & 0xF] & 0xFF;
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }

    //this rotates the word one byte to the left
    private int RotWord(int word) {
        int a0 = (word >>> 24) & 0xFF;
        int a1 = (word >>> 16) & 0xFF;
        int a2 = (word >>> 8) & 0xFF;
        int a3 = (word & 0xFF);

        return (a1 << 24 | a2 << 16 | a3 << 8 | a0);
    }

    //this method adds padding to the very last block,
    //so that it has a length of 16bytes and can be processed by c()
    //it uses the PKCS#7 scheme
    private byte[] addPadding(byte[] cleartext) {
        int padding = 16 - (cleartext.length % 16);

        byte[] padded_cleartext = new byte[cleartext.length + padding];
        System.arraycopy(cleartext, 0, padded_cleartext, 0, cleartext.length);

        for (int i = 0; i < padding; i++) {
            padded_cleartext[cleartext.length + i] = (byte) padding;
        }

        return padded_cleartext;
    }

    /**
     * This method encrypts a String
     * @param cleartext the text to be encrypted
     * @param key the key used for encryption needs to be 8 ints for AES_256, 6 ints for AES_192, and 4 ints for AES_128
     * @return the encrypted string represented by a byte[]
     */
    public byte[] encrypt(String cleartext, int[] key) {
        return encrypt(cleartext.getBytes(), key);
    }

    /**
     * This method encrypts a byte[]
     * @param cleartext the values to be encrypted
     * @param key the key used for encryption needs to be 8 ints for AES_256, 6 ints for AES_192, and 4 ints for AES_128
     * @return the encrypted byte[]
     */
    public byte[] encrypt(byte[] cleartext, int[] key) {

        if(key.length != Nk) throw new InvalidKeyException();


        //the key expansion is performed
        byte[] key_bytes = new byte[Nk * 4];
        for (int i = 0; i < key.length; i++) {
            key_bytes[i << 2] = (byte) ((key[i] >> 24) & 0xFF);
            key_bytes[(i << 2) + 1] = (byte) ((key[i] >> 16) & 0xFF);
            key_bytes[(i << 2) + 2] = (byte) ((key[i] >> 8) & 0xFF);
            key_bytes[(i << 2) + 3] = (byte) (key[i] & 0xFF);
        }
        int[] expanded_key_schedule = key_expansion(key_bytes);

        byte[] ciphertext;
        return switch (mode) {

            //Electronic cookbook mode (ECB) is VERY unsafe
            //since it always uses the same key for all blocks
            //therefore two identical cleartext blocks will produce IDENTICAL ciphertext blocks!!!
            case ECB -> {

                //add padding and fill the padded cleartext into a 2D array
                byte[] padded_cleartext = addPadding(cleartext);
                byte[][] inputs = new byte[padded_cleartext.length / 16][16];
                for (int i = 0; i < padded_cleartext.length; i++) {
                    inputs[i / 16][i % 16] = padded_cleartext[i];
                }

                ciphertext = new byte[padded_cleartext.length];


                for (int i = 0; i < inputs.length; i++) {

                    //encrypt every cleartext block
                    byte[][] state = c(inputs[i], expanded_key_schedule);

                    //flatten and concatenate the 2D state array into the ciphertext
                    for (int j = 0; j < 4; j++) {
                        for (int k = 0; k < 4; k++) {
                            ciphertext[(i << 4) + ((k << 2) + j)] = state[j][k];
                        }
                    }
                }

                yield ciphertext;
            }

            //Cipher Block Chaining mode is the default mode within this implementation
            //it xors the previous ciphertext block and the current cleartext block together
            //before passing the result into the encryption method.
            //this creates a dependency on the previous block
            case CBC -> {

                //add padding and fill the padded cleartext into a 2D array
                byte[] padded_cleartext = addPadding(cleartext);
                byte[][] inputs = new byte[padded_cleartext.length / 16][16];
                for (int i = 0; i < padded_cleartext.length; i++) {
                    inputs[i / 16][i % 16] = padded_cleartext[i];
                }

                //we introduce a 16 byte nonce as our initial block
                byte[] lastBlock = rng.generateSeed(16);

                //this nonce is prepended onto the ciphertext since it has to be known for the decryption
                ciphertext = new byte[padded_cleartext.length + lastBlock.length];
                System.arraycopy(lastBlock, 0, ciphertext, 0, lastBlock.length);


                for (int i = 0; i < inputs.length; i++) {

                    //xor the current cleartext block and the last ciphertext block
                    byte[][] state = c(bytes_xor(inputs[i], lastBlock), expanded_key_schedule);

                    //flatten the 2D state into ciphertext and the lastBlock
                    for (int j = 0; j < 4; j++) {
                        for (int k = 0; k < 4; k++) {
                            ciphertext[lastBlock.length + (i << 4) + ((k << 2) + j)] = state[j][k];
                            lastBlock[(k << 2) + j] = state[j][k];
                        }
                    }
                }

                yield ciphertext;
            }

            //with Counter mode, rather than encrypting the plaintext with the c() function
            //we instead create a keystream with our encryption function,
            //each byte from the keystream is xored with the plaintext to create the ciphertext
            case CTR -> {

                //just like with CBC we need an IV, this one is only 12 byte large,
                //as we append the 4 byte counter for every block
                final byte[] IV = rng.generateSeed(12);
                int ctr = 0;

                //the IV needs to be prepended onto the ciphertext for decryption
                ciphertext = new byte[cleartext.length + IV.length];
                System.arraycopy(IV, 0, ciphertext, 0, IV.length);

                byte[] block;
                for (int i = 0; i < cleartext.length; i++) {

                    //create every block by concatenating the IV and the incremented counter
                    block = build_CTR_block(IV, ctr++);

                    byte[][] state = c(block, expanded_key_schedule);

                    //flatten the state into a 1D bytestream and xor the plaintext to create the ciphertext
                    for (int j = 0; j < 4; j++) {
                        for (int k = 0; k < 4; k++) {
                            int currIndex = (i << 4) + ((k << 2) + j);

                            if (currIndex < cleartext.length) {
                                ciphertext[IV.length + currIndex] = (byte) (cleartext[currIndex] ^ state[j][k]);
                            }
                        }
                    }

                }

                //no need for padding as the plaintext is never passed into c()
                yield ciphertext;
            }
        };

    }


    //concatenate the IV and ctr to a 16 byte block
    private byte[] build_CTR_block(byte[] IV, int ctr){
        byte[] block = new byte[16];

        for (int i = 0; i < 12; i++) {
            block[i] = IV[i];
        }
        for (int i = 12; i < 16; i++) {
            block[i] = (byte) (ctr >> ((3 - (i - 12)) << 3) & 0xFF);
        }

        return block;
    }


    //same as Arrays.copyOfRange()
    //from is inclusive
    //to is exclusive
    private int[] array_copy_of_range(int[] arr, int from, int to) {
        int[] o = new int[to - from];
        System.arraycopy(arr, from, o, 0, to - from);
        return o;
    }


    //xor two arrays of bytes
    private byte[] bytes_xor(byte[] p, byte[] c) {

        byte[] o = new byte[p.length];
        for (int i = 0; i < p.length; i++) {
            o[i] = (byte) (((p[i] & 0xFF) ^ (c[i] & 0xFF)) & 0xFF);
        }
        return o;
    }


    /**
     * The decryption function
     * @param ciphertext encrypted ciphertext
     * @param key the key, 8 ints for AES_256, 6 ints for AES_192, 4 ints for AES_128
     * @return the decrypted plaintext
     */
    public byte[] decrypt(byte[] ciphertext, int[] key) {

        if(key.length != Nk) throw new InvalidKeyException();


        // key expansion
        byte[] key_bytes = new byte[Nk * 4];
        for (int i = 0; i < key.length; i++) {
            key_bytes[i << 2] = (byte) ((key[i] >> 24) & 0xFF);
            key_bytes[(i << 2) + 1] = (byte) ((key[i] >> 16) & 0xFF);
            key_bytes[(i << 2) + 2] = (byte) ((key[i] >> 8) & 0xFF);
            key_bytes[(i << 2) + 3] = (byte) (key[i] & 0xFF);
        }

        int[] expanded_key_schedule = key_expansion(key_bytes);


        return switch (mode) {

            //same logic as the encryption. Again DO NOT USE THIS!
            case ECB -> {
                byte[][] inputs = new byte[ciphertext.length / 16][16];
                byte[] cleartext = new byte[ciphertext.length];

                for (int i = 0; i < ciphertext.length; i++) {
                    inputs[i / 16][i % 16] = ciphertext[i];
                }

                for (int i = 0; i < inputs.length; i++) {

                    // ic() is the inverse c function
                    byte[][] state = ic(inputs[i], expanded_key_schedule);

                    for (int j = 0; j < 4; j++) {
                        for (int k = 0; k < 4; k++) {
                            cleartext[(i << 4) + ((k << 2) + j)] = state[j][k];
                        }
                    }
                }

                //naturally the padding is removed
                cleartext = removePadding(cleartext);

                yield  cleartext;
            }

            //the decryption is very similar to the encryption
            case CBC -> {
                byte[][] inputs = new byte[ciphertext.length / 16][16];
                byte[] lastBlock = new byte[16];
                byte[] cleartext = new byte[ciphertext.length - 16];

                for (int i = 0; i < ciphertext.length; i++) {
                    inputs[i / 16][i % 16] = ciphertext[i];
                }

                //fetch the IV
                System.arraycopy(ciphertext, 0, lastBlock, 0, lastBlock.length);

                for (int i = 1; i < inputs.length; i++) {

                    //the decryption function is applied BEFORE the xor
                    byte[][] state = ic(inputs[i], expanded_key_schedule);
                    byte[] flattened_state = new byte[16];

                    for (int j = 0; j < 4; j++) {
                        for (int k = 0; k < 4; k++) {
                            flattened_state[((k << 2) + j)] = state[j][k];
                        }
                    }

                    //the decrypted block is xored with the prior encrypted block
                    byte[] final_state = bytes_xor(flattened_state, lastBlock);
                    lastBlock = inputs[i];
                    System.arraycopy(final_state, 0, cleartext, (i - 1) << 4, 16);
                }

                yield removePadding(cleartext);
            }

            //here the decryption is exactly the same as the encryption, as xor is its own inverse.
            case CTR -> {

                //the IV is read and stored
                final byte[] IV = new byte[12];
                System.arraycopy(ciphertext, 0, IV, 0, 12);
                int ctr = 0;

                //same size as the ciphertext - the length of the IV, as there is no padding
                byte[] cleartext = new byte[ciphertext.length - 12];

                byte[] block;
                for (int i = 0; i < cleartext.length; i++) {

                    block = build_CTR_block(IV, ctr++);

                    byte[][] state = c(block, expanded_key_schedule);

                    for (int j = 0; j < 4; j++) {
                        for (int k = 0; k < 4; k++) {
                            int currIndex = 12 +  (i << 4) + ((k << 2) + j);

                            if (currIndex < ciphertext.length) {
                                cleartext[(i << 4) + ((k << 2) + j)] = (byte) (ciphertext[currIndex] ^ state[j][k]);
                            }
                        }
                    }

                }

                yield cleartext;
            }
        };
    }

    private byte[] removePadding(byte[] cleartext) {
        byte padding = (byte) (cleartext[cleartext.length - 1] & 0xFF);

        if(padding < 0 || padding > 16) {
            throw new IllegalStateException();
        }

        for (int i = cleartext.length - padding; i < cleartext.length; i++) {
            if(cleartext[i] != padding) throw new IllegalStateException("was: " + cleartext[i] + " at {" + i + "} instead of: " + padding);
        }

        byte[] sans_padding = new byte[cleartext.length - padding];
        System.arraycopy(cleartext, 0, sans_padding, 0, sans_padding.length);

        return sans_padding;
    }

    private byte[][] ic(byte[] ciphertext, int[] key_schedule){
        byte[][] state = new byte[4][Nb];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = ciphertext[(j << 2) + i];
            }
        }

        AddRoundKey(state, array_copy_of_range(key_schedule, Nb*Nr, (Nr+1) * Nb));

        for(int round = Nr - 1; round >= 1; round--) {
            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, array_copy_of_range(key_schedule, round*Nb, (round+1) * Nb));
            InvMixColumns(state);
        }

        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, array_copy_of_range(key_schedule, 0, Nb));

        return state;
    }

    private void InvShiftRows(byte[][] state) {
        byte[][] tmp = new byte[4][4];
        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 4; i++) {
                tmp[j][i] = state[j][(i - j + 4) % 4];
            }
        }

        for (int j = 0; j < 4; j++) {
            for (int i = 0; i < 4; i++) {
                state[j][i] = tmp[j][i];
            }
        }
    }

    private void InvSubBytes(byte[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = InvSBox[((state[i][j] & 0xFF) >> 4) & 0xF][(state[i][j] & 0xFF) & 0xF];
            }
        }
    }

    private void InvMixColumns(byte[][] state) {
        byte[][] tmp = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            byte[] column = new byte[4];
            for (int j = 0; j < 4; j++) {
                column[j] = state[j][i];
            }

            for (int j = 0; j < 4; j++) {
                tmp[j][i] = rowTimesCol(inv_a[j], column);
            }
        }

        for (int j = 0; j < 4; j++) {
            System.arraycopy(tmp[j], 0, state[j], 0, 4);
        }
    }
}
