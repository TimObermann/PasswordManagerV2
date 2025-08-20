package passwordmanager.gui;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.security.SecureRandom;

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

        entryfactory = new EntryFactory();
        random = new SecureRandom();

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
    private final EntryFactory entryfactory;
    private final SecureRandom random;

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

    private final char[] charset = new char[94];

    private String generateRandomPassword() {
        StringBuilder p = new StringBuilder();

        for (int i = 0; i < 128; i++) {
             p.append(charset[random.nextInt(94)]);
        }

        return p.toString();
    }

}
