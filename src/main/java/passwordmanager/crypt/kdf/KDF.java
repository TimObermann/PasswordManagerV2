package passwordmanager.crypt.kdf;

public interface KDF {
    byte[] generate(byte[] password, byte[] salt, int dkLen);
}
