package passwordmanager.gui;

import org.json.JSONObject;

public record LoginData(String vaultName, byte[] derivedVaultPassword, JSONObject header){}
