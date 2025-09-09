package passwordmanager.gui;

import org.json.JSONObject;
import passwordmanager.crypt.hash.SHA2;
import passwordmanager.crypt.kdf.scrypt.Scrypt;
import passwordmanager.crypt.mac.HMAC;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.stream.Stream;

public class LoginForm implements UserDialogueListener{

    private LoginListener loginListener;
    private UserModificationListener userListener;

    private JTextField UsernameField;
    private JPanel loginPanel;
    private JPasswordField PasswordField;
    private JButton LoginButton;
    private JButton AddUserButton;
    private JButton DeleteUserButton;
    private JPanel EntryPanel;

    private final Scrypt scrypt = new Scrypt();
    private final HMAC hmac = new HMAC(new SHA2());

    private final String VAULTS = "resources";

    public LoginForm(LoginListener loginListener, UserModificationListener userListener) {
        this.loginListener = loginListener;
        this.userListener = userListener;

        loginPanel.setOpaque(true);
        EntryPanel.setOpaque(true);
        UsernameField.setOpaque(true);
        PasswordField.setOpaque(true);
        LoginButton.setOpaque(true);

        AddUserButton.setText("+");
        DeleteUserButton.setText("-");

        loginPanel.setBackground(Color.DARK_GRAY);
        EntryPanel.setBackground(Color.DARK_GRAY);
        UsernameField.setBackground(Color.GRAY);
        PasswordField.setBackground(Color.GRAY);
        LoginButton.setBackground(Color.GRAY);

        PasswordField.setBorder(BorderFactory.createLineBorder(Color.BLACK, 2));
        UsernameField.setBorder(BorderFactory.createLineBorder(Color.BLACK, 2));
        LoginButton.setBorder(BorderFactory.createLineBorder(Color.BLUE, 1));

        UsernameField.setForeground(Color.WHITE);
        PasswordField.setForeground(Color.WHITE);
        LoginButton.setForeground(Color.WHITE);

        LoginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                LoginData data = login(UsernameField.getText(), PasswordField.getPassword());

                if(data == null) {
                    loginListener.onLoginFailure();
                    return;
                }

                loginListener.onLoginSuccess(data);
                UsernameField.setText("");
                PasswordField.setText("");
            }
        });
        AddUserButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                addUser();
            }
        });
        DeleteUserButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                deleteUser();
            }
        });
    }

    LoginData login(String username, char[] password) {

        byte[] password_bytes = GUI_Util.toBytes(password);
        GUI_Util.zeroArray(password);

        List<Path> headers = getVaults();

        for (Path header : headers) {

            LoginData data;
            if((data = tryVault(header, username, password_bytes)) != null) {
                return data;
            }
        }

        return null;
    }

    private LoginData tryVault(Path header, String username, byte[] password) {
        try {
            byte[] header_bytes = Files.readAllBytes(header);
            JSONObject header_json = new JSONObject(new String(header_bytes, StandardCharsets.UTF_8));
            JSONObject master = header_json.getJSONObject("MASTER");

            byte[] salt = GUI_Util.deserialize(master.getString("SALT"));
            int n = master.getInt("N");
            int r = master.getInt("R");
            int p = master.getInt("P");

            try {
                byte[] derived_vault_password = scrypt.generate(password, salt, n, r, p, 32);

                String vaultName = GUI_Util.serialize(hmac.generateTag(username.getBytes(StandardCharsets.UTF_8), derived_vault_password));
                String storedVaultName = header_json.getString("VAULT_ID");

                if(GUI_Util.safeCmp(GUI_Util.deserialize(vaultName), GUI_Util.deserialize(storedVaultName))) {
                    return new LoginData(vaultName, derived_vault_password, header_json);
                }

            }
            catch (IllegalArgumentException _) {}

            return null;

        } catch (IOException e) {
            throw new VaultSecurityViolation();
        }
    }

    private List<Path> getVaults() {
        try (Stream<Path> paths = Files.walk(Path.of(VAULTS))){
            return paths
                    .filter(Files::isRegularFile)
                    .filter(path -> path.getFileName().toString().equals("vault_header.json"))
                    .toList();
        } catch (IOException e) {
            throw new VaultSecurityViolation();
        }
    }

    public JPanel getPanel() {
        return loginPanel;
    }

    private void addUser() {
        new UserDialogue(this, true);
    }

    private void deleteUser() {
        new UserDialogue(this, false);
    }

    @Override
    public void onCreate(UserData data) {
        if(validUserData(data)) userListener.onUserCreateSuccess(data);
        else userListener.onUserCreateFailure();
    }

    private boolean validUserData(UserData data) {
        return true;
    }

    @Override
    public void onDelete(UserData data) {
        byte[] password = GUI_Util.toBytes(data.password());
        GUI_Util.zeroArray(data.password());

        List<Path> headers = getVaults();

        for (Path header : headers) {

            LoginData da;
            if((da = tryVault(header, data.username(), password)) != null) {
                GUI_Util.zeroArray(password);
                userListener.onUserDeleteSuccess(da.vaultName());
                return;
            }
        }

        GUI_Util.zeroArray(password);
        userListener.onUserDeleteFailure();
    }
}