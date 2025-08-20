package passwordmanager.filemanager;

import passwordmanager.crypt.hash.HMAC;
import passwordmanager.crypt.hash.SHA2;
import passwordmanager.gui.Entry;

import java.io.BufferedReader;
import java.io.File;
import org.json.JSONObject;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.net.URI;
import java.util.stream.Collectors;

public class FileManager {

    private final SHA2 hashingAlgorithm;
    private final HMAC hmac;

    public FileManager(){
        hashingAlgorithm = new SHA2();
        hmac = new HMAC(hashingAlgorithm);
    }

    private String readFile(File f) {
       try {
           BufferedReader br = new BufferedReader(new FileReader(f));
           return br.lines().collect(Collectors.joining());

       } catch (FileNotFoundException e) {
           return "";
       }
    }

    private JSONObject getIndex() {
        File index = new File(URI.create("../../../resources/index.json"));
        String content = readFile(index);

        JSONObject obj = new JSONObject(content);
        hashingAlgorithm.insert(content.getBytes());

        String expected_hash = obj.getString("last-instance");
        String actual_hash = bytes_to_string(hashingAlgorithm.generate());

        if(!expected_hash.equals(actual_hash)) {
            throw new AuthenticityViolationError();
        }

        return obj;
    }

    private void writeFile(File f, String content) {

    }

    private void updateIndex(Entry entry) {
        JSONObject indexJSON = getIndex();
        hashingAlgorithm.reset();

        hashingAlgorithm.insert(entry.getWebsite());
        hashingAlgorithm.insert(entry.getUsername());

        indexJSON.getJSONArray("titles").put(bytes_to_string(hashingAlgorithm.generate()));

        indexJSON.remove("last-instance");

        //byte[] key = new byte[];

       // hmac.generate(indexJSON.toString().getBytes(), key,64);

        indexJSON.put("last-instance", bytes_to_string(hashingAlgorithm.generate()));

        writeFile(new File(URI.create("../../../resources/index.json")), indexJSON.toString());
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

    public String getMasterHash () {
        JSONObject index = getIndex();
        return index.getString("master-hash");
    }

    public void store(Entry entry) {

    }
}
