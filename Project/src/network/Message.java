package network;

import org.json.JSONObject;

public class Message {
    public MessageType type;
    public JSONObject payload;

    public Message(MessageType type, JSONObject payload) {
        this.type = type;
        this.payload = payload;
    }

    public String toJSON() {
        JSONObject obj = new JSONObject();
        obj.put("type", type.toString());
        obj.put("payload", payload);
        return obj.toString();
    }

    public static Message fromJSON(String json) {
        JSONObject obj = new JSONObject(json);
        return new Message(
            MessageType.valueOf(obj.getString("type")),
            obj.getJSONObject("payload")
        );
    }
}