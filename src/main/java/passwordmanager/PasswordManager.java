package passwordmanager;

import passwordmanager.gui.Dashboard;
import passwordmanager.gui.LoginForm;
import passwordmanager.gui.LoginListener;
import passwordmanager.gui.Main;

import javax.swing.*;
import java.awt.*;

public class PasswordManager {

    public static void main(String[] args) {
        SwingUtilities.invokeLater(Main::new);
    }
}
