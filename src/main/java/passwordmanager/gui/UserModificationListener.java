package passwordmanager.gui;

public interface UserModificationListener {
    void onUserCreateSuccess(UserData data);
    void onUserDeleteSuccess(String vaultName);
    void onUserDeleteFailure();
    void onUserCreateFailure();
}
