package passwordmanager.gui;

import javax.swing.*;
import java.awt.event.*;

public class UserDialogue extends JDialog {
    private JPanel contentPane;
    private JButton buttonOK;
    private JButton buttonCancel;
    private JPasswordField PasswordField;
    private JTextField UsernameField;

    private UserDialogueListener listener;
    private final boolean type;
    /// /
    public UserDialogue(UserDialogueListener listener, boolean type) {

        this.listener = listener;
        this.type = type;

        setContentPane(contentPane);
        setModal(true);
        getRootPane().setDefaultButton(buttonOK);

        buttonOK.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                onOK();
            }
        });

        buttonCancel.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                onCancel();
            }
        });

        // call onCancel() when cross is clicked
        setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            public void windowClosing(WindowEvent e) {
                onCancel();
            }
        });

        // call onCancel() on ESCAPE
        contentPane.registerKeyboardAction(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                onCancel();
            }
        }, KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0), JComponent.WHEN_ANCESTOR_OF_FOCUSED_COMPONENT);

        pack();
        setVisible(true);
    }

    private void onOK() {
        // add your code here

       if(type) {
           listener.onCreate(new UserData(UsernameField.getText(), PasswordField.getPassword()));
       }
       else {
           listener.onDelete(new UserData(UsernameField.getText(), PasswordField.getPassword()));
       }

        dispose();
    }

    private void onCancel() {
        // add your code here if necessary

        dispose();
    }
}
