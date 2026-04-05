package network;

import org.json.JSONObject;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class Message {
    public String type;
    public JSONObject fields;

    public Message(String type, JSONObject fields) {
        this.type = type;
        this.fields = fields;
    }

    public byte[] toBytes() {
        JSONObject root = new JSONObject();
        root.put("type", type);
        for (String key : fields.keySet()) {
            root.put(key, fields.get(key));
        }
        String json = root.toString();
        byte[] jsonBytes = json.getBytes(StandardCharsets.UTF_8);
        byte[] lenBytes = new byte[4];
        lenBytes[0] = (byte) ((jsonBytes.length >> 24) & 0xFF);
        lenBytes[1] = (byte) ((jsonBytes.length >> 16) & 0xFF);
        lenBytes[2] = (byte) ((jsonBytes.length >> 8) & 0xFF);
        lenBytes[3] = (byte) (jsonBytes.length & 0xFF);
        byte[] out = new byte[4 + jsonBytes.length];
        System.arraycopy(lenBytes, 0, out, 0, 4);
        System.arraycopy(jsonBytes, 0, out, 4, jsonBytes.length);
        return out;
    }

    public static Message readFromStream(InputStream in) throws IOException {
        byte[] lenBytes = new byte[4];
        int read = 0;
        while (read < 4) {
            int r = in.read(lenBytes, read, 4 - read);
            if (r == -1) throw new EOFException();
            read += r;
        }
        int length = ((lenBytes[0] & 0xFF) << 24) |
                ((lenBytes[1] & 0xFF) << 16) |
                ((lenBytes[2] & 0xFF) << 8)  |
                (lenBytes[3] & 0xFF);
        byte[] jsonBytes = new byte[length];
        read = 0;
        while (read < length) {
            int r = in.read(jsonBytes, read, length - read);
            if (r == -1) throw new EOFException();
            read += r;
        }
        String json = new String(jsonBytes, StandardCharsets.UTF_8);
        JSONObject obj = new JSONObject(json);
        String type = obj.getString("type");
        obj.remove("type");
        return new Message(type, obj);
    }
}