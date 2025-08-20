package passwordmanager.gui;

public class Entry {
    private byte[] username;
    private byte[] website;
    private byte[] password;

    public Entry(byte[] website, byte[] username, byte[] password){
        this.website = website;
        this.username = username;
        this.password = password;
    }

    public byte[] getUsername() {
        return username;
    }

    public byte[] getWebsite() {
        return website;
    }

    public byte[] getPassword() {
        return password;
    }
}

