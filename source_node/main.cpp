#include <Servo.h>
#include <EEPROM.h>
#include <RH_RF95.h>
#include <ArduinoJson.h>
#include <AESLib.h>
#include "GateNode.h"
#include "GateCommands.h"

// Forward declarations
void startProvisioning();
void sendProvisionRequest();
void checkProvisionResponse();
size_t encrypt(uint8_t* output, const uint8_t* input, size_t len, const uint8_t* key);
bool decrypt(uint8_t* output, const uint8_t* input, size_t len, const uint8_t* key);
void hex2bin(const char* hex, uint8_t* bin, size_t bin_len);

struct Config {
  char id[16];
  uint8_t psk[16];  // Store as binary (16 bytes)
  char location[32];
  char name[32];
  uint32_t counter;
};

Servo gate;
RH_RF95 lora(10, 2);  // CS=10, INT=2
Config config;
bool provisioned = false;
const uint8_t masterPSK[16] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC,0xBA,0x98,0x76,0x54,0x32,0x10};

struct AppConfig {
    char id[16];
    uint8_t psk[16];
    uint32_t counter;
};

class NodeFactory {
public:
    static GateNode createNode() {
        static AES128CBCStrategy cryptoStrategy;
        static Servo gate;
        static CommandProcessor cmdProcessor(gate);
        return GateNode(&cryptoStrategy, &cmdProcessor);
    }
};

GateNode node = NodeFactory::createNode();

void setup() {
  Serial.begin(115200);
  EEPROM.get(0, config);
  if(config.id[0] == 0xFF) {  // Check for unprogrammed EEPROM
    startProvisioning();
  } else {
    provisioned = true;
  }
  
  gate.attach(9);
  if (!lora.init()) {
    Serial.println("LoRa init failed!");
    while(1);
  }
  
  // Match bridge's LoRa settings
  lora.setFrequency(433.0);
  lora.setTxPower(13);
  lora.setSpreadingFactor(7);
  lora.setSignalBandwidth(125000);
  lora.setCodingRate4(5);

  node.initialize();
}

void loop() {
  node.run();
  delay(5000);
}

void startProvisioning() {
  while(!provisioned) {
    sendProvisionRequest();
    delay(10000);
    checkProvisionResponse();
  }
}

void sendProvisionRequest() {
  StaticJsonDocument<128> doc;
  doc["type"] = "prov_req";
  doc["hw_id"] = "nano_gate";
  
  String jsonStr;
  serializeJson(doc, jsonStr);
  
  uint8_t encrypted[128];
  size_t len = encrypt(encrypted, (uint8_t*)jsonStr.c_str(), jsonStr.length(), masterPSK);
  lora.send(encrypted, len);
  lora.waitPacketSent();
}

void checkProvisionResponse() {
  if(lora.available()) {
    uint8_t buf[RH_RF95_MAX_MESSAGE_LEN];
    uint8_t len = sizeof(buf);
    
    if(lora.recv(buf, &len)) {
      uint8_t decrypted[128];
      if(decrypt(decrypted, buf, len, masterPSK)) {
        StaticJsonDocument<128> doc;
        DeserializationError error = deserializeJson(doc, (char*)decrypted);
        
        if(!error && doc["id"] && doc["psk"]) {
          strncpy(config.id, doc["id"], 16);
          hex2bin(doc["psk"], config.psk, 16);
          EEPROM.put(0, config);
          provisioned = true;
        }
      }
    }
  }
}

size_t encrypt(uint8_t* output, const uint8_t* input, size_t len, const uint8_t* key) {
  uint8_t iv[16];
  for(int i=0; i<16; i++) iv[i] = random(256);
  memcpy(output, iv, 16);

  size_t padded_len = ((len + 15) / 16) * 16;
  uint8_t pad_value = padded_len - len;
  memset(output+16, pad_value, padded_len);
  memcpy(output+16, input, len);

  AESLib aesLib;
  aesLib.set_paddingmode(paddingMode::CMS);
  aesLib.encrypt(output+16, padded_len, output+16, key, 16, iv);
  
  return padded_len + 16;
}

bool decrypt(uint8_t* output, const uint8_t* input, size_t len, const uint8_t* key) {
  if(len < 16 || (len-16) % 16 != 0) return false;
  
  uint8_t iv[16];
  memcpy(iv, input, 16);
  
  uint8_t* temp = new uint8_t[len-16];
  memcpy(temp, input+16, len-16);
  
  AESLib aesLib;
  aesLib.set_paddingmode(paddingMode::CMS);
  size_t decrypted_len = aesLib.decrypt(temp, len-16, output, key, 16, iv);
  
  if(decrypted_len == 0) {
    delete[] temp;
    return false;
  }
  
  delete[] temp;
  return true;
}

void hex2bin(const char* hex, uint8_t* bin, size_t bin_len) {
  for(size_t i=0; i<bin_len; i++) {
    sscanf(hex + i*2, "%2hhx", &bin[i]);
  }
}

void sendHeartbeat() {
  StaticJsonDocument<128> doc;
  doc["id"] = config.id;
  doc["ctr"] = config.counter++;
  doc["servo"] = gate.read();
  
  String jsonStr;
  serializeJson(doc, jsonStr);
  
  uint8_t encrypted[128];
  size_t len = encrypt(encrypted, (uint8_t*)jsonStr.c_str(), jsonStr.length(), config.psk);
  lora.send(encrypted, len);
  lora.waitPacketSent();
}

void checkCommands() {
  if(lora.available()) {
    uint8_t buf[RH_RF95_MAX_MESSAGE_LEN];
    uint8_t len = sizeof(buf);
    
    if(lora.recv(buf, &len)) {
      uint8_t decrypted[128];
      if(decrypt(decrypted, buf, len, config.psk)) {
        StaticJsonDocument<128> doc;
        DeserializationError error = deserializeJson(doc, (char*)decrypted);
        
        if(!error && doc["cmd"] && strcmp(doc["id"], config.id) == 0) {
          if(strcmp(doc["cmd"], "open") == 0) gate.write(180);
          else if(strcmp(doc["cmd"], "close") == 0) gate.write(0);
        }
      }
    }
  }
} 