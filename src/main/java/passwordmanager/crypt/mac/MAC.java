package passwordmanager.crypt.mac;

public interface MAC {
    byte[] generateTag(byte[] message, byte[] key);
}
