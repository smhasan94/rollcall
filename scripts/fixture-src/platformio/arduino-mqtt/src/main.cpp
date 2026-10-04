// rollcall fixture source (SHA-131): Wi-Fi + MQTT + a button, using each of the three
// lib_deps so the library dependency finder links all of them. Never flashed; it only has
// to build.
#include <Arduino.h>
#include <ArduinoJson.h>
#include <OneButton.h>
#include <PubSubClient.h>
#include <WiFi.h>

static WiFiClient net;
static PubSubClient mqtt(net);
static OneButton button(0, true);

static void publishPress() {
    JsonDocument doc;
    doc["event"] = "press";
    doc["uptime_ms"] = millis();
    char payload[128];
    size_t n = serializeJson(doc, payload, sizeof(payload));
    mqtt.publish("rollcall/fixture/button", reinterpret_cast<const uint8_t *>(payload), n);
}

void setup() {
    Serial.begin(115200);
    WiFi.mode(WIFI_STA);
    WiFi.begin("rollcall-fixture", "not-a-real-password");
    mqtt.setServer("mqtt.invalid", 1883);
    button.attachClick(publishPress);
}

void loop() {
    if (WiFi.status() == WL_CONNECTED && !mqtt.connected()) {
        mqtt.connect("rollcall-fixture");
    }
    mqtt.loop();
    button.tick();
    delay(10);
}
