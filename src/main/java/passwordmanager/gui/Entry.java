package passwordmanager.gui;

public class Entry {
    private byte[] username;
    private String website;
    private byte[] password;

    public Entry(String website, byte[] username, byte[] password){
        this.website = website;
        this.username = username;
        this.password = password;
    }

    public byte[] getUsername() {
        return username;
    }

    public String getWebsite() {
        return website;
    }

    public byte[] getPassword() {
        return password;
    }
}

