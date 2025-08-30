package passwordmanager.gui;

import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import org.json.JSONObject;
import passwordmanager.crypt.cipher.aes.AES;
import passwordmanager.crypt.hash.HMAC;
import passwordmanager.crypt.hash.SHA2;
import passwordmanager.crypt.kdf.PBKDF2;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.URI;
import java.security.SecureRandom;
import java.util.stream.Collectors;


public class GUI {
    //components
    public JPanel passwordPanel;
    private JList<String> entries;
    private JButton AddButton;
    private JTextField websiteTextField;
    private JTextField usernameTextField;
    private JPasswordField passwordPasswordField;
    private JButton RandomPasswordButton;
    private JPanel AddPanel;
    private JScrollPane EntriesPanel;
    private JTabbedPane InformationTabs;
    private DefaultListModel<String> listModel;

    public GUI() {
        passwordPanel.setOpaque(true);
        entries.setOpaque(true);
        AddPanel.setOpaque(true);
        EntriesPanel.setOpaque(true);

        AddPanel.setBackground(Color.GRAY);

        EntriesPanel.setBackground(Color.GRAY);
        EntriesPanel.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);

        entries.setBackground(Color.DARK_GRAY);
        entries.setSelectionBackground(Color.CYAN);
        entries.setForeground(Color.WHITE);

        listModel = new DefaultListModel<>();
        entries.setModel(listModel);

        for (int i = 0; i < charset.length; i++) {
            charset[i] = (char) (33 + i);
        }

        AddButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                addEntry(websiteTextField.getText(), usernameTextField.getText(), formatPasswordInput(passwordPasswordField.getPassword()));
            }
        });
        RandomPasswordButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                passwordPasswordField.setText(generateRandomPassword());
            }
        });
    }

    //function
    private int[] key = new int[]{
        0x00010203,
                0x04050607,
                0x08090a0b,
                0x0c0d0e0f,
                0x10111213,
                0x14151617,
                0x18191a1b,
                0x1c1d1e1f
    };

    private final EntryFactory entryfactory = new EntryFactory();
    private final SecureRandom random = new SecureRandom();
    private final PBKDF2 kdf = new PBKDF2();
    private final SHA2 hashingAlgorithm = new SHA2();
    private final HMAC hmac = new HMAC(new SHA2());
    private final AES encryptionAlgorithm = new AES();
    private byte[] derivedKey;

    private final String RESOURCES_PATH = "../../../resources/";
    private final String INDEX_INTEGRITY_HASH = "last-instance";
    private final String ENTRY_WEBSITE = "website_name";
    private final String FILE_NAME_HASH = "file_name";
    private final String FILE_INTEGRITY_HASH = "integrity_hash";


    private byte[] formatPasswordInput(char[] c) {
        byte[] b = new byte[c.length * 2];

        for (int i = 0; i < c.length; i++) {
            b[i << 1] = (byte) ((c[i] >> 8) & 0xFF);
            b[(i << 1) + 1] = (byte) (c[i] & 0xFF);
        }
        return b;
    }

    private void addEntry(String website, String username, byte[] password) {
        entryfactory.createEntry(website, username, password, key);
        listModel.addElement(website);
    }

    private boolean login() {
        Argon2 argon = Argon2Factory.create(Argon2Factory.Argon2Types.ARGON2id, 16, 32);
        String trueMasterHash = getMasterHash();

        char[] password = passwordPasswordField.getPassword();

        try {

            if(argon.verify(trueMasterHash, password)) {
                derivedKey = kdf.generate(password, 600000, 64);
                return true;
            }
            else return false;

        } finally {
            argon.wipeArray(password);
        }

    }

    private final char[] charset = new char[94];

    private String generateRandomPassword() {
        StringBuilder p = new StringBuilder();

        for (int i = 0; i < 128; i++) {
             p.append(charset[random.nextInt(94)]);
        }

        return p.toString();
    }

    private String readFile(File f) {
        try(BufferedReader br = new BufferedReader(new FileReader(f));){
            return br.lines().collect(Collectors.joining());
        } catch (IOException e) {
            throw new SecureReadException();
        }
    }

    private JSONObject getIndex() {
        File index = new File(URI.create(RESOURCES_PATH + "index.json"));
        String content = readFile(index);

        JSONObject obj = new JSONObject(content);
        String expected_hash = obj.getString(INDEX_INTEGRITY_HASH);

        obj.remove(INDEX_INTEGRITY_HASH);

        hashingAlgorithm.insert(obj.toString().getBytes());
        String actual_hash = bytes_to_string(hashingAlgorithm.generate());

        obj.put(INDEX_INTEGRITY_HASH, expected_hash);

        if(!expected_hash.equals(actual_hash)) {
            throw new AuthenticityViolationError();
        }

        return obj;
    }

    private void writeFile(File f, String content) {
        try(BufferedWriter bw = new BufferedWriter(new FileWriter(f))) {
            bw.write(content);
        }
        catch (IOException e) {
            throw new SecureWriteException();
        }

    }

    private void updateIndex(Entry entry, byte[] newFileHash) {
        JSONObject indexJSON = getIndex();
        hashingAlgorithm.reset();

        hashingAlgorithm.insert(entry.getWebsite().getBytes());
        hashingAlgorithm.insert(entry.getUsername());

        JSONObject newEntry = new JSONObject();
        newEntry.put(ENTRY_WEBSITE, entry.getWebsite());
        newEntry.put(FILE_NAME_HASH, bytes_to_string(hashingAlgorithm.generate()));
        newEntry.put(FILE_INTEGRITY_HASH, bytes_to_string(newFileHash));

        indexJSON.getJSONArray("titles").put(newEntry);

        indexJSON.remove(INDEX_INTEGRITY_HASH);

        hmac.generate(indexJSON.toString().getBytes(), derivedKey,64);

        indexJSON.put(INDEX_INTEGRITY_HASH, bytes_to_string(hashingAlgorithm.generate()));
        writeFile(new File(URI.create(RESOURCES_PATH + "index.json")), indexJSON.toString());
    }

    private static String bytes_to_string(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            hexString.append(String.format("%02x", b));
        }
        return hexString.toString();
    }


    private byte[] string_to_bytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len >> 1];

        for (int i = 0; i < len; i += 2) {
            data[i >> 1] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    public String getMasterHash() {
        JSONObject index = getIndex();
        return index.getString("master-hash");
    }

    public void store(Entry entry) {

    }
}
