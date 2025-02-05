#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <SPIFFS.h>
#include <RH_RF95.h>
#include <ArduinoJson.h>
#include <AES.h>
#include <Crypto.h>

// Configuration
#define LORA_FREQ 868.0
#define PROV_TOKEN_TIMEOUT 300000  // 5 minutes
AES128 aes;

struct Node {
  String id;
  String psk;
  String location;
  String name;
  String status = "OFFLINE";
  String servo = "UNKNOWN";
  uint32_t counter = 0;
  unsigned long lastSeen = 0;
};

std::vector<Node> nodes;
std::map<String, unsigned long> provTokens;

RH_RF95 lora(D8, D3);
ESP8266WebServer server(80);
const byte masterPSK[16] = { /* Your master PSK here */ };

String encrypt(String plaintext, const byte* key) {
  byte iv[16], cipher[plaintext.length() + 16];
  for(int i=0; i<16; i++) iv[i] = random(256);
  
  aes.setKey(key, 16);
  aes.encryptCBC((byte*)plaintext.c_str(), cipher, iv, plaintext.length());
  
  String result;
  result.reserve(sizeof(iv) + plaintext.length());
  result += String((char*)iv, sizeof(iv));
  result += String((char*)cipher, plaintext.length());
  return result;
}

String decrypt(String ciphertext, const byte* key) {
  byte iv[16], plain[ciphertext.length() - 16];
  memcpy(iv, ciphertext.c_str(), 16);
  memcpy(plain, ciphertext.c_str()+16, ciphertext.length()-16);
  
  aes.setKey(key, 16);
  aes.decryptCBC(plain, plain, iv, ciphertext.length()-16);
  
  return String((char*)plain).substring(0, ciphertext.length()-16);
}

void setup() {
  SPIFFS.begin();
  WiFi.begin("SSID", "PASS");
  while(WiFi.status() != WL_CONNECTED) delay(500);
  
  lora.init();
  lora.setFrequency(LORA_FREQ);
  
  server.on("/status", HTTP_GET, handleStatus);
  server.on("/provision", HTTP_POST, handleProvision);
  server.on("/control", HTTP_POST, handleControl);
  server.begin();
  
  loadNodes();
}

void loop() {
  server.handleClient();
  checkHeartbeats();
  processLoRa();
  cleanProvTokens();
}

// --------------------- API Handlers ---------------------
void handleProvision() {
  DynamicJsonDocument doc(256);
  deserializeJson(doc, server.arg("plain"));
  
  String token = doc["token"];
  if(!validateProvToken(token)) {
    server.send(403, "text/plain", "Invalid token");
    return;
  }

  Node node;
  node.id = "nano_" + String(random(1000,9999));
  node.psk = String(random(0xFFFF), HEX) + String(random(0xFFFF), HEX);
  node.location = doc["location"];
  node.name = doc["name"];
  
  String response;
  DynamicJsonDocument respDoc(256);
  respDoc["id"] = node.id;
  respDoc["psk"] = node.psk;
  response = encrypt(respDoc.as<String>(), masterPSK);
  
  nodes.push_back(node);
  saveNodes();
  server.send(200, "text/plain", response);
}

void handleControl() {
  String hmac = server.header("X-HMAC");
  String payload = server.arg("plain");
  
  if(!verifyHMAC(payload, hmac)) {
    server.send(401, "text/plain", "Invalid HMAC");
    return;
  }

  DynamicJsonDocument doc(256);
  deserializeJson(doc, payload);
  String targetID = doc["id"];
  
  for(auto& node : nodes) {
    if(node.id == targetID) {
      String command = "{\"cmd\":\"" + doc["action"].as<String>() + "\"}";
      sendLoRa(command, node.psk.c_str());
      server.send(200, "text/plain", "Command sent");
      return;
    }
  }
  server.send(404, "text/plain", "Node not found");
}

// --------------------- LoRa Communication ---------------------
void processLoRa() {
  if(lora.available()) {
    uint8_t buf[RH_RF95_MAX_MESSAGE_LEN];
    uint8_t len = sizeof(buf);
    
    if(lora.recv(buf, &len)) {
      String encrypted((char*)buf, len);
      for(auto& node : nodes) {
        String decrypted = decrypt(encrypted, (const byte*)node.psk.c_str());
        if(decrypted.length() > 0) {
          handleNodeMessage(decrypted, node);
          break;
        }
      }
    }
  }
}

void handleNodeMessage(String message, Node& node) {
  DynamicJsonDocument doc(256);
  deserializeJson(doc, message);
  
  node.lastSeen = millis();
  node.status = "ONLINE";
  node.counter = doc["counter"];
  
  if(doc.containsKey("servo")) {
    node.servo = doc["servo"];
  }
  
  if(doc.containsKey("prov_req")) {
    handleProvisionRequest(doc["hw_id"], node);
  }
}

// --------------------- Security Functions ---------------------
bool verifyHMAC(String payload, String receivedHmac) {
  // Implement HMAC verification
  return true;
}

void cleanProvTokens() {
  unsigned long now = millis();
  auto it = provTokens.begin();
  while(it != provTokens.end()) {
    if(now - it->second > PROV_TOKEN_TIMEOUT) {
      it = provTokens.erase(it);
    } else {
      ++it;
    }
  }
}