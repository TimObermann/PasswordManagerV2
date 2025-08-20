package passwordmanager.gui;

import passwordmanager.crypt.aes.AES;
import passwordmanager.crypt.aes.AES_MODE;
import passwordmanager.crypt.aes.AES_SIZE;

public class EntryFactory {
    private AES crypt;

    public EntryFactory() {
        crypt = new AES(AES_SIZE.AES_256, AES_MODE.CBC);
    }

    public Entry createEntry(String website, String username, byte[] password, int[] key) {
        return new Entry(crypt.encrypt(website, key), crypt.encrypt(username, key), crypt.encrypt(password, key));
    }
}
