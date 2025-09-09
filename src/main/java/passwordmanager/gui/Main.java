package passwordmanager.gui;

import javax.swing.*;
import java.awt.*;

public class Main extends JFrame implements LoginListener, UserModificationListener {

    private final int VERSION = 0x10;

    private LoginData userData;
    private JPanel interfacePanel;
    private CardLayout layout;

    private LoginForm login;
    private Dashboard dashboard;

    public Main() {

        layout = new CardLayout();
        interfacePanel = new JPanel(layout);


        login = new LoginForm(this, this);
        dashboard = new Dashboard(this);

        interfacePanel.add(login.getPanel(), "LOGIN");
        interfacePanel.add(dashboard.getPanel(), "DASHBOARD");

        layout.show(interfacePanel, "LOGIN");

        setContentPane(interfacePanel);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        getContentPane().setBackground(Color.DARK_GRAY);
        pack();
        setExtendedState(JFrame.MAXIMIZED_BOTH);
        setVisible(true);
    }

    @Override
    public void onLogout() {
        layout.show(interfacePanel, "LOGIN");
    }

    @Override
    public void onLoginSuccess(LoginData data) {
        this.userData = data;
        dashboard.login(data);
        layout.show(interfacePanel, "DASHBOARD");
    }

    @Override
    public void onLoginFailure() {
        JOptionPane.showMessageDialog(this, "Wrong Username or Password");
    }

    @Override
    public void onUserCreateSuccess(UserData data) {
        dashboard.createUser(data.username(), data.password(), VERSION);
    }

    @Override
    public void onUserDeleteSuccess(String vaultName) {
        dashboard.deleteUser(vaultName);
    }

    @Override
    public void onUserCreateFailure() {
        JOptionPane.showMessageDialog(this, "could not create this user");
    }

    @Override
    public void onUserDeleteFailure() {
        JOptionPane.showMessageDialog(this, "there was an error in the deletion of the user. Consider deleting the files manually");
    }
}
