package passwordmanager.gui;

import org.json.JSONArray;
import org.json.JSONObject;
import passwordmanager.crypt.cipher.aes.AES;
import passwordmanager.crypt.cipher.chacha.XChaCha20_Poly1305;
import passwordmanager.crypt.hash.Blake2b;
import passwordmanager.crypt.hash.Hash;
import passwordmanager.crypt.kdf.scrypt.Scrypt;
import passwordmanager.crypt.hash.SHA2;
import passwordmanager.crypt.mac.HMAC;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.*;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.*;
import java.util.List;


public class Dashboard {
    //components
    private JPanel dashboardPanel;
    private JList<String> entries;
    private JButton AddButton;
    private JTextField websiteTextField;
    private JTextField usernameTextField;
    private JPasswordField passwordPasswordField;
    private JPanel AddPanel;
    private JScrollPane EntriesPanel;
    private JCheckBox RandomPasswordCheckBox;
    private JPasswordField selectedPasswordField;
    private JTextField selectedUsernameField;
    private JLabel SelectedService_Label;
    private JCheckBox unsafeCheckBox;
    private JButton AutoCopyButton;
    private JButton revealButton;
    private JButton copyToClipboardButton;
    private JButton DeleteButton;
    private JPasswordField changeNewPasswordField;
    private JPasswordField changeOldPasswordField;
    private JButton changePasswordButton;
    private JCheckBox DeleteCheckBox;
    private JLabel ChangePasswordLabel;
    private JPanel deleteAndChangePanel;
    private JPanel SelectedDataPanel;
    private JPanel CopyPanel;
    private JPanel SelectAndCopyPanel;
    private JPanel ChangePasswordPanel;
    private JPanel DeletePanel;
    private JPanel OpenDataPanel;
    private JPanel UnsafeCopyPanel;
    private JButton SettingsButton;
    private JPanel SettingsPanel;
    private JPanel deleteAndSettingsPanel;
    private JTextField SearchBar;
    private JPanel SearchBarPanel;
    private JLabel StoredAccoundsLabel;
    private JButton LogoutButton;
    private DefaultListModel<String> listModel;

    public Dashboard(LoginListener listener) {

        this.listener = listener;

        SecureRandom tmp;
        try{
            tmp = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            tmp = new SecureRandom();
        }

        random = tmp;

        SettingsButton.setIcon(new ImageIcon("src/main/resources/user_settings.png"));
        LogoutButton.setIcon(new ImageIcon("src/main/resources/logout.png"));

        Border black = BorderFactory.createLineBorder(Color.BLACK, 5);
        Border outer = BorderFactory.createLineBorder(Color.darkGray, 5);
        Border inner = BorderFactory.createEmptyBorder(10, 10, 10, 10);

        Border border = BorderFactory.createCompoundBorder(outer, inner);
        black = BorderFactory.createCompoundBorder(black, inner);
        dashboardPanel.setOpaque(true);
        entries.setOpaque(true);
        SettingsPanel.setOpaque(true);

        AddPanel.setOpaque(true);
        EntriesPanel.setOpaque(true);
        OpenDataPanel.setOpaque(true);
        SearchBarPanel.setOpaque(true);

        deleteAndChangePanel.setOpaque(true);
        SelectAndCopyPanel.setOpaque(true);
        deleteAndSettingsPanel.setOpaque(true);

        DeletePanel.setOpaque(true);
        CopyPanel.setOpaque(true);
        UnsafeCopyPanel.setOpaque(true);
        SelectedDataPanel.setOpaque(true);
        ChangePasswordPanel.setOpaque(true);

        SettingsButton.setOpaque(true);
        LogoutButton.setOpaque(true);

        AddPanel.setBackground(Color.GRAY);
        OpenDataPanel.setBackground(Color.GRAY);
        deleteAndChangePanel.setBackground(Color.GRAY);
        SelectAndCopyPanel.setBackground(Color.GRAY);
        SettingsPanel.setBackground(Color.DARK_GRAY);
        deleteAndSettingsPanel.setBackground(Color.GRAY);
        SearchBarPanel.setBackground(Color.DARK_GRAY);

        DeletePanel.setBackground(Color.GRAY);
        CopyPanel.setBackground(Color.GRAY);
        UnsafeCopyPanel.setBackground(Color.GRAY);
        SelectedDataPanel.setBackground(Color.GRAY);
        ChangePasswordPanel.setBackground(Color.GRAY);

        SettingsButton.setBackground(Color.DARK_GRAY);
        SettingsButton.setBorderPainted(false);
        LogoutButton.setBackground(Color.DARK_GRAY);
        LogoutButton.setBorderPainted(false);

        SearchBar.setBorder(black);
        AddPanel.setBorder(border);
        DeletePanel.setBorder(border);
        SelectedDataPanel.setBorder(border);
        ChangePasswordPanel.setBorder(border);
        CopyPanel.setBorder(border);

        EntriesPanel.setBackground(Color.GRAY);
        EntriesPanel.setComponentOrientation(ComponentOrientation.RIGHT_TO_LEFT);

        entries.setBackground(Color.DARK_GRAY);
        entries.setSelectionBackground(Color.CYAN);
        entries.setForeground(Color.WHITE);



        listModel = new DefaultListModel<>();
        entries.setModel(listModel);


        StringBuilder s = new StringBuilder();
        for (int i = 0; i < 128; i++) {
            s.append(0);
        }
        passwordPasswordField.setText(s.toString());
        hasObscuredRandomPassword = true;


        AddButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                addEntry(websiteTextField.getText(), usernameTextField.getText(), passwordPasswordField.getPassword());
            }
        });
        RandomPasswordCheckBox.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if(e.getStateChange() == ItemEvent.SELECTED) {

                    StringBuilder s = new StringBuilder();
                    for (int i = 0; i < 128; i++) {
                        s.append(0);
                    }
                    passwordPasswordField.setText(s.toString());
                    hasObscuredRandomPassword = true;
                }
                else {

                    if(hasObscuredRandomPassword) {
                        passwordPasswordField.setText("");
                    }

                    hasObscuredRandomPassword = false;
                }
            }
        });
        unsafeCheckBox.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {

                if(e.getStateChange() == ItemEvent.SELECTED) {
                    revealButton.setEnabled(true);
                    copyToClipboardButton.setEnabled(true);
                }
                if(e.getStateChange() == ItemEvent.DESELECTED) {
                    revealButton.setEnabled(false);
                    copyToClipboardButton.setEnabled(false);
                }

            }
        });
        revealButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
        copyToClipboardButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
        AutoCopyButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
        changePasswordButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });
        DeleteCheckBox.addItemListener(new ItemListener() {
            @Override
            public void itemStateChanged(ItemEvent e) {
                if(e.getStateChange() == ItemEvent.SELECTED) {
                    DeleteButton.setEnabled(true);
                }
                if(e.getStateChange() == ItemEvent.DESELECTED) {
                    DeleteButton.setEnabled(false);
                }
            }
        });
        DeleteButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

            }
        });

        SearchBar.addKeyListener(new KeyAdapter() {
            @Override
            public void keyTyped(KeyEvent e) {
                search(e.getKeyChar());
            }
        });
        LogoutButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                logout();
            }
        });
    }

    private boolean hasObscuredRandomPassword;

    private final LoginListener listener;
    private final SecureRandom random;
    private final Scrypt kdf = new Scrypt();
    private final Hash hash = new SHA2();
    private final Blake2b blake = new Blake2b();
    private final HMAC hmac = new HMAC(new SHA2());
    private final XChaCha20_Poly1305 cipher = new XChaCha20_Poly1305();
    private final AES aes = new AES();

    private final String INDEX_FILE = "index.ref";
    private final String VAULT_HEADER = "vault_header.json";
    private final String DATABASE = "database.db";
    private final String VAULTS = "resources";
    private final String VAULT_PREFIX = "vault-";

    private byte[] derivedKey = null;
    private String vaultName = null;

    private final Path vaults = Path.of(VAULTS);
    private JSONObject header = null;
    private RadixTree prefixTree = new RadixTree();

    private String canconical_serializeJSON(JSONObject obj) {
        StringBuilder str = new StringBuilder();

        List<String> keys = new ArrayList<>(obj.keySet());
        Collections.sort(keys);

        str.append("{");

        for (int i = 0; i < keys.size(); i++) {
            String key = keys.get(i);
            Object value = obj.get(key);

            str.append("\"").append(key).append("\":");

            if (value instanceof JSONObject) {
                str.append(canconical_serializeJSON((JSONObject) value)); // Recurse for nested objects
            } else if (value instanceof JSONArray) {
                str.append(canconical_serializeJSON((JSONArray) value)); // Handle arrays
            } else if (value instanceof String) {
                str.append("\"").append(value).append("\"");
            } else {
                str.append(value.toString());
            }

            if (i < keys.size() - 1) {
                str.append(",");
            }
        }

        str.append("}");
        return str.toString();
    }
    private String canconical_serializeJSON(JSONArray arr) {
        StringBuilder str = new StringBuilder();
        str.append("[");
        for (int i = 0; i < arr.length(); i++) {
            Object value = arr.get(i);

            if (value instanceof JSONObject) {
                str.append(canconical_serializeJSON((JSONObject) value));
            } else if (value instanceof JSONArray) {
                str.append(canconical_serializeJSON((JSONArray) value));
            } else if (value instanceof String) {
                str.append("\"").append(value).append("\"");
            } else {
                str.append(value.toString());
            }

            if (i < arr.length() - 1) {
                str.append(",");
            }
        }
        str.append("]");
        return str.toString();
    }

    private void updateIndex(byte[] plain_index_data) {

        if(header == null) throw new VaultSecurityViolation();

        String auth_json = header.getString("AUTH");
        byte[] authTag = GUI_Util.deserialize(auth_json);


        JSONObject master = header.getJSONObject("MASTER");
        JSONObject index = header.getJSONObject("INDEX");

        String master_salt_json = master.getString("SALT");
        byte[] master_salt = GUI_Util.deserialize(master_salt_json);

        JSONObject kdf_params = index.getJSONObject("KDF_PARAMS");

        String index_salt_json = kdf_params.getString("SALT");
        byte[] index_salt =  GUI_Util.deserialize(index_salt_json);

        String vaultName = header.getString("VAULT_ID");
        int vault_version = header.getInt("VAULT_VERSION");

        int index_N = kdf_params.getInt("N");
        int index_P = kdf_params.getInt("P");
        int index_R = kdf_params.getInt("R");

        String nonce_json = index.getString("NONCE");
        int[] nonce = GUI_Util.bytes_to_ints(GUI_Util.deserialize(nonce_json));

        byte[] aad = createIndexAAD(master_salt, index_salt, nonce, authTag, vaultName, vault_version);

        byte[] derived_key_index = kdf.scrypt(derivedKey, index_salt, index_N, index_R, index_P, 32);

        int[] derived_key_index_as_ints = GUI_Util.bytes_to_ints(derived_key_index);
        byte[] encrypted_index_data = cipher.encrypt(plain_index_data, derived_key_index_as_ints, nonce, aad);

        GUI_Util.zeroArray(derived_key_index);
        GUI_Util.zeroArray(derived_key_index_as_ints);

        Path index_path = vaults.resolve(Path.of(VAULT_PREFIX + vaultName)).resolve(INDEX_FILE);
        secure_write(encrypted_index_data, index_path);
    }
    private byte[] readIndex() {

        if(derivedKey == null || header == null) throw new VaultSecurityViolation();

        byte[] authTag = verifyHeader();

        JSONObject master = header.getJSONObject("MASTER");
        JSONObject index = header.getJSONObject("INDEX");

        String master_salt_json = master.getString("SALT");
        byte[] master_salt = GUI_Util.deserialize(master_salt_json);

        JSONObject kdf_params = index.getJSONObject("KDF_PARAMS");

        String index_salt_json = kdf_params.getString("SALT");
        byte[] index_salt = GUI_Util.deserialize(index_salt_json);

        String vaultName = header.getString("VAULT_ID");
        int vault_version = header.getInt("VAULT_VERSION");

        int index_N = kdf_params.getInt("N");
        int index_P = kdf_params.getInt("P");
        int index_R = kdf_params.getInt("R");

        byte[] derived_key_index = kdf.scrypt(derivedKey, index_salt, index_N, index_R, index_P, 32);

        String nonce_json = index.getString("NONCE");
        int[] nonce = GUI_Util.bytes_to_ints(GUI_Util.deserialize(nonce_json));

        byte[] aad = createIndexAAD(master_salt, index_salt, nonce, authTag, vaultName, vault_version);

        Path index_path = Path.of(INDEX_FILE);
        index_path = vaults.resolve(VAULT_PREFIX + vaultName).resolve(index_path);

        int[] derived_index_key_as_ints = null;
        byte[] encrypted_index = null;
        byte[] decrypted_index = null;

        try{

            derived_index_key_as_ints = GUI_Util.bytes_to_ints(derived_key_index);

            encrypted_index = Files.readAllBytes(index_path);
            decrypted_index = cipher.decrypt(encrypted_index, derived_index_key_as_ints, nonce, aad);

            GUI_Util.zeroArray(derived_key_index);
            GUI_Util.zeroArray(derived_index_key_as_ints);
            GUI_Util.zeroArray(encrypted_index);

            return decrypted_index;

        } catch (IOException e) {
            GUI_Util.zeroArray(derived_index_key_as_ints);
            GUI_Util.zeroArray(encrypted_index);
            GUI_Util.zeroArray(derived_key_index);

            throw new VaultSecurityViolation();
        }
    }
    private void deserializeIndex(byte[] plain_index_data, RadixTree prefixTree) {

        if(plain_index_data.length < 6) {
            return;
        }

        char[] words = GUI_Util.toChars(plain_index_data);

        int i = 0;
        while (i < words.length) {
            char[] tmp = new char[2];
            System.arraycopy(words, i, tmp, 0, 2);
            i += 2;

            char[] buff = new char[GUI_Util.toInt(tmp)];

            System.arraycopy(words, i, buff, 0, buff.length);
            i += buff.length;

            System.arraycopy(words, i, tmp, 0, 2);
            int offset = GUI_Util.toInt(tmp);
            i += 2;

            System.arraycopy(words, i, tmp, 0, 2);
            int length = GUI_Util.toInt(tmp);
            i += 2;

            Pointer ptr = new Pointer(offset, length);

            prefixTree.insert(buff, ptr);
        }
    }
    private byte[] serializeSingleIndex(char[] word, RadixTree prefixTree) {
        Pointer ptr = prefixTree.lookup(word);
        char[] out = new char[word.length + 6];

        int offset = 0;
        System.arraycopy(GUI_Util.toChars(word.length), 0, out, offset, 2);
        offset += 2;
        System.arraycopy(word, 0, out, offset, word.length);
        offset += word.length;
        System.arraycopy(GUI_Util.toChars(ptr.getOffset()), 0, out, offset, 2);
        offset += 2;
        System.arraycopy(GUI_Util.toChars(ptr.getLength()), 0, out, offset, 2);

        return GUI_Util.toBytes(out);
    }
    private byte[] serializeIndex(RadixTree prefixTree) {
        Map<RadixTree.CharArray, Pointer> nodes = prefixTree.collectAllEntries();

        int totalSiteNameSize = nodes.keySet().stream().mapToInt(n -> n.getArray().length).sum();
        char[] data = new char[totalSiteNameSize + nodes.size() * 6];
        int offset = 0;

        for (Map.Entry<RadixTree.CharArray, Pointer> entry : nodes.entrySet()) {
            char[] site = entry.getKey().getArray();
            System.arraycopy(GUI_Util.toChars(site.length), 0, data, offset, 2);
            offset += 2;
            System.arraycopy(site, 0, data, offset, site.length);
            offset += site.length;
            System.arraycopy(GUI_Util.toChars(entry.getValue().getOffset()), 0, data, offset, 2);
            offset += 2;
            System.arraycopy(GUI_Util.toChars(entry.getValue().getLength()), 0, data, offset, 2);
            offset += 2;
        }

        return GUI_Util.toBytes(data);
    }

    private void readHeader() {

        if(derivedKey == null) throw new VaultSecurityViolation();
        Path header_path = vaults.resolve(Path.of(VAULT_PREFIX + vaultName)).resolve(Path.of(VAULT_HEADER));

        try {
            byte[] header_bytes = Files.readAllBytes(header_path);
            header = new JSONObject(new String(header_bytes, StandardCharsets.UTF_8));

            verifyHeader();
        } catch (IOException e) {
            throw new VaultSecurityViolation();
        }

    }
    private byte[] verifyHeader() {
        JSONObject deepCopy = new JSONObject(header.toString());

        String auth_json = deepCopy.getString("AUTH");
        byte[] authTag = GUI_Util.deserialize(auth_json);

        deepCopy.remove("AUTH");
        if(!hmac.verify(canconical_serializeJSON(deepCopy).getBytes(StandardCharsets.UTF_8), derivedKey, authTag)) {
            throw new VaultSecurityViolation();
        }

        return authTag;
    }

    private Pointer secure_append(byte[] encrypted_data, Path destPath) {
        Path tmp_indx;
        byte[] og_data = null;
        int len = encrypted_data.length;
        int off = -1;

        try {
            tmp_indx = Files.createTempFile("tmpFile", ".tmp");
        } catch (IOException e) {
            throw new VaultSecurityViolation();
        }

        if(tmp_indx == null) throw new VaultSecurityViolation();

        try (OutputStream o = Files.newOutputStream(tmp_indx, StandardOpenOption.WRITE)){
            if(Files.exists(destPath)) {
                og_data = Files.readAllBytes(destPath);
                o.write(og_data);
                off = og_data.length;
                GUI_Util.zeroArray(og_data);
            }

            o.write(encrypted_data);
            GUI_Util.zeroArray(encrypted_data);
        } catch (IOException e) {

            len = -1;
            off = -1;

            if(og_data != null) {
                GUI_Util.zeroArray(og_data);
            }
            GUI_Util.zeroArray(encrypted_data);

            throw new VaultSecurityViolation();
        }

        try {
            Files.move(tmp_indx, destPath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new VaultSecurityViolation();
        }

        if(len > 0 && off >= 0) {
            return new Pointer(off, len);
        }
        else {
            return null;
        }
    }
    private void secure_write(byte[] encrypted_data, Path destPath) {
        Path tmp_indx;

        try {
            tmp_indx = Files.createTempFile("tmpFile", ".tmp");
        } catch (IOException e) {
            throw new VaultSecurityViolation();
        }

        if(tmp_indx == null) throw new VaultSecurityViolation();

        try (OutputStream o = Files.newOutputStream(tmp_indx, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)){
            o.write(encrypted_data);
            GUI_Util.zeroArray(encrypted_data);
        } catch (IOException e) {
            GUI_Util.zeroArray(encrypted_data);
            throw new VaultSecurityViolation();
        }

        try {
            Files.move(tmp_indx, destPath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new VaultSecurityViolation();
        }
    }
    private void secure_write(String public_data, Path destPath) {
        Path tmp_indx;

        try {
            tmp_indx = Files.createTempFile("tmpFile", ".tmp");
        } catch (IOException e) {
            throw new VaultSecurityViolation();
        }

        if(tmp_indx == null) throw new VaultSecurityViolation();

        try (OutputStream o = Files.newOutputStream(tmp_indx, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)){
            o.write(public_data.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            throw new VaultSecurityViolation();
        }

        try {
            Files.move(tmp_indx, destPath, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
        } catch (IOException e) {
            throw new VaultSecurityViolation();
        }
    }

    void createUser(String username, char[] password_chars, int vault_version) {

        byte[] password = GUI_Util.toBytes(password_chars);
        GUI_Util.zeroArray(password_chars);

        final int master_N = 65536;
        final int master_R = 8;
        final int master_P = 1;
        final int index_N = 65536;
        final int index_R = 8;
        final int index_P = 1;

        byte[] salt = new byte[16];
        random.nextBytes(salt);

        byte[] derived_vault_password = kdf.generate(password, salt, master_N, master_R, master_P, 32);
        GUI_Util.zeroArray(password);

        byte[] username_bytes = username.getBytes(StandardCharsets.UTF_8);

        String vaultName = GUI_Util.serialize(hmac.generateTag(username_bytes, derived_vault_password));
        GUI_Util.zeroArray(username_bytes);

        Path vault = vaults.resolve(Path.of(VAULT_PREFIX + vaultName));
        Path header = Path.of(VAULT_HEADER);
        Path index = Path.of(INDEX_FILE);
        Path database = Path.of(DATABASE);

        header = vault.resolve(header);
        index = vault.resolve(index);
        database = vault.resolve(database);

        try {

            Files.createDirectories(vault);
            Files.createFile(header);
            Files.createFile(index);
            Files.createFile(database);

        } catch (IOException e) {

            try {
                Files.deleteIfExists(header);
                Files.deleteIfExists(index);
                Files.deleteIfExists(database);
                Files.deleteIfExists(vault);

            } catch (IOException fe) {
                System.err.println("Could not delete remainder of file structure for vault-" + vaultName);
            }

            e.printStackTrace();

            throw new VaultSecurityViolation();
        }

        byte[] index_salt = new byte[16];
        random.nextBytes(index_salt);

        byte[] derived_index_key = kdf.scrypt(derived_vault_password, index_salt, index_N, index_R, index_P, 32);

        int[] nonce = random.ints(6).toArray();

        JSONObject baseHeader = new JSONObject();
        JSONObject master_params = new JSONObject();
        JSONObject index_params = new JSONObject();

        master_params.put("SALT", GUI_Util.serialize(salt));
        master_params.put("N", master_N);
        master_params.put("R", master_R);
        master_params.put("P", master_P);

        JSONObject index_kdf_params = new JSONObject();
        index_kdf_params.put("SALT", GUI_Util.serialize(index_salt));
        index_kdf_params.put("N", index_N);
        index_kdf_params.put("R", index_R);
        index_kdf_params.put("P", index_P);

        index_params.put("KDF_PARAMS", index_kdf_params);
        index_params.put("NONCE", GUI_Util.serialize(nonce));

        baseHeader.put("VAULT_ID", vaultName);
        baseHeader.put("VAULT_VERSION", vault_version);
        baseHeader.put("MASTER", master_params);
        baseHeader.put("INDEX", index_params);

        byte[] authTag = hmac.generateTag(canconical_serializeJSON(baseHeader).getBytes(StandardCharsets.UTF_8), derived_vault_password);

        baseHeader.put("AUTH", GUI_Util.serialize(authTag));

        byte[] aad_index = createIndexAAD(salt, index_salt, nonce, authTag, vaultName, vault_version);
        byte[] encrypted_index_data = cipher.encrypt("".getBytes(StandardCharsets.UTF_8), GUI_Util.bytes_to_ints(derived_index_key), nonce, aad_index);

        secure_write(encrypted_index_data, index);
        secure_write(canconical_serializeJSON(baseHeader), header);
    }
    void deleteUser(String vaultName) {

        Path toDelete = vaults.resolve(Path.of(VAULT_PREFIX + vaultName));

        if(!Files.exists(toDelete)) return;

        try {

            Files.walkFileTree(toDelete, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                    Files.delete(file);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult postVisitDirectory(Path dir, IOException exc) throws IOException {
                    Files.delete(dir);
                    return FileVisitResult.CONTINUE;
                }
            });

        } catch (IOException e) {
            throw new VaultSecurityViolation();
        }

        if(Files.exists(toDelete)) throw new IllegalStateException();
    }

    private Pointer writeToDatabase(byte[] encryptedData) {
        Path database = vaults.resolve(VAULT_PREFIX + vaultName).resolve(DATABASE);
        Pointer ret = secure_append(encryptedData, database);

        if(ret == null) {
            throw new VaultSecurityViolation();
        }

        return ret;
    }
    private byte[] readFromDatabase(Pointer ptr) {
        Path database = vaults.resolve(VAULT_PREFIX + vaultName).resolve(DATABASE);

        try(FileChannel channel = FileChannel.open(database, StandardOpenOption.READ)) {
            ByteBuffer ret = ByteBuffer.allocate(ptr.getLength());
            channel.position(ptr.getOffset());
            channel.read(ret);
            ret.flip();

            byte[] out = new byte[ret.remaining()];
            ret.get(out);

            return out;
        } catch (IOException e) {
            throw new VaultSecurityViolation();
        }
    }
    private void vacuum() {
        java.util.Map<RadixTree.CharArray, Pointer> accounts = prefixTree.collectAllEntries();

        Path index = vaults.resolve(Path.of(VAULT_PREFIX + vaultName)).resolve(INDEX_FILE);
        Path tmp = null;

        try {
            tmp = Files.createTempFile("tmpfile", "tmp");

            for(Pointer ptr : accounts.values()) {
                byte[] entry = readFromDatabase(ptr);

                Pointer newPos = secure_append(entry, tmp);

                if(newPos == null) throw new VaultSecurityViolation();

                ptr.setOffset(newPos.getOffset());
            }

            Files.move(tmp, index, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);

        } catch (IOException e) {

            if(tmp != null) {
                try {
                    Files.delete(tmp);
                }
                catch (IOException _) {}
            }

            throw new VaultSecurityViolation();
        }

        byte[] newIndex = serializeIndex(prefixTree);
        updateIndex(newIndex);
    }

    void login(LoginData data) {
        this.derivedKey = data.derivedVaultPassword();
        this.vaultName = data.vaultName();
        this.header = data.header();

        byte[] index = readIndex();

        deserializeIndex(index, prefixTree);
        listModel.addAll(prefixTree.getAllWords());
    }
    void logout() {
        byte[] clear_index_data = serializeIndex(prefixTree);
        updateIndex(clear_index_data);

        vacuum();

        prefixTree.zero();
        prefixTree = new RadixTree();

        listModel.clear();

        listener.onLogout();
    }

    private void addEntry(String account, String username, char[] password) {

        int[] nonce = random.ints(6).toArray();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        byte[] password_bytes = GUI_Util.toBytes(password);
        GUI_Util.zeroArray(password);

        byte[] derivedEntryPassword = kdf.generate(password_bytes, salt, 32);


        if(hasObscuredRandomPassword) {
            password = generateRandomPassword(128);
        }

        byte[] plaintextBlock = new byte[password_bytes.length + username.getBytes(StandardCharsets.UTF_8).length];
        int offset = 0;
        System.arraycopy(password_bytes, 0, plaintextBlock, offset, password_bytes.length);
        offset += password_bytes.length;
        GUI_Util.zeroArray(password_bytes);
        System.arraycopy(username.getBytes(StandardCharsets.UTF_8), 0, plaintextBlock, offset, username.getBytes(StandardCharsets.UTF_8).length);
        offset += username.getBytes(StandardCharsets.UTF_8).length;

        int[] derivedKeyINTS = GUI_Util.bytes_to_ints(derivedEntryPassword);
        byte[] ciphertext = cipher.encrypt(username.getBytes(StandardCharsets.UTF_8), derivedKeyINTS, nonce, derivedKey);

        GUI_Util.zeroArray(derivedKeyINTS);
        GUI_Util.zeroArray(plaintextBlock);
        GUI_Util.zeroArray(derivedEntryPassword);

        offset = 0;
        byte[] ciphertext_with_meta = new byte[salt.length + (nonce.length << 2) + ciphertext.length];
        System.arraycopy(salt, 0, ciphertext_with_meta, offset, salt.length);
        offset += salt.length;
        System.arraycopy(GUI_Util.toBytes(nonce), 0, ciphertext_with_meta, offset, (nonce.length << 2));
        offset += (nonce.length << 2);
        System.arraycopy(ciphertext, 0, ciphertext_with_meta, offset, ciphertext.length);

        GUI_Util.zeroArray(ciphertext);

        Pointer location = writeToDatabase(ciphertext_with_meta);
        prefixTree.insert(account.toCharArray(), location);
        listModel.addElement(account);
    }
    private void deleteEntry() {

    }

    private char[] searchbuffer = new char[0];
    private int search_index = 0;
    private void search(char c) {

        if(prefixTree == null) throw new VaultSecurityViolation();

        if(searchbuffer.length == search_index) {
            char[] tmp = new char[searchbuffer.length << 3];
            System.arraycopy(searchbuffer, 0, tmp, 0, search_index);

            searchbuffer = tmp;
        }

        searchbuffer[search_index++] = c;

        List<String> wordPointers = prefixTree.query(searchbuffer);
        listModel.clear();
        listModel.addAll(wordPointers);
    }

    private byte[] createIndexAAD(byte[] master_salt, byte[] index_salt, int[] nonce, byte[] authTag, String vaultName, int vault_version) {

        byte[] aad_index = new byte[index_salt.length + (nonce.length << 2) + master_salt.length + authTag.length + GUI_Util.deserialize(vaultName).length + 4];
        int offset = 0;
        System.arraycopy(index_salt, 0, aad_index, offset, index_salt.length);
        offset += index_salt.length;
        System.arraycopy(GUI_Util.toBytes(nonce), 0, aad_index, offset, (nonce.length << 2));
        offset += (nonce.length << 2);
        System.arraycopy(master_salt, 0, aad_index, offset, master_salt.length);
        offset += master_salt.length;
        System.arraycopy(authTag, 0, aad_index, offset, authTag.length);
        offset += authTag.length;
        System.arraycopy(GUI_Util.deserialize(vaultName), 0, aad_index, offset, GUI_Util.deserialize(vaultName).length);
        offset += GUI_Util.deserialize(vaultName).length;
        System.arraycopy(GUI_Util.toBytes(vault_version), 0, aad_index, offset, 4);

        return aad_index;
    }
    private char[] generateRandomPassword(int dkLen) {

        char[] charset = new char[94];
        for (int i = 0; i < 94; i++) {
            charset[i] = (char) (i + 33);
        }

        char[] out = new char[dkLen];

        for (int i = 0; i < dkLen; i++) {
             out[i] = (charset[random.nextInt(94)]);
        }

        return out;
    }

    public JPanel getPanel() {
        return dashboardPanel;
    }

}
