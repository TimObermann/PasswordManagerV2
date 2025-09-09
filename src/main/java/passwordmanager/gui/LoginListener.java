package passwordmanager.gui;

public interface LoginListener {
    void onLoginSuccess(LoginData data);
    void onLoginFailure();
    void onLogout();
}
