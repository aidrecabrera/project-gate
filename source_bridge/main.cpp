#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <LittleFS.h>
#include <RH_RF95.h>
#include <ArduinoJson.h>
#include <bearssl/bearssl_hmac.h>
#include <bearssl/bearssl_block.h>
#include <bearssl/bearssl_rand.h>
#include <Ticker.h>
#include <ctype.h>
#include <WiFiManager.h>
#include <TimeLib.h>

#define LOG(fmt, ...) Serial.printf("[%lu][%s] " fmt "\n", millis(), __func__, ##__VA_ARGS__)

void bin2hex(const uint8_t *bin, size_t len, char *hex);

#pragma GCC optimize("-O3")
const uint8_t masterPSK[16] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
br_hmac_drbg_context rng_ctx;

void bin2hex(const uint8_t *bin, size_t len, char *hex)
{
  const char *hex_chars = "0123456789ABCDEF";
  for (size_t i = 0; i < len; i++)
  {
    hex[i * 2] = hex_chars[(bin[i] >> 4) & 0xF];
    hex[i * 2 + 1] = hex_chars[bin[i] & 0xF];
  }
  hex[len * 2] = '\0';
}

static void hex2bin(const char *hex, uint8_t *bin, size_t bin_len)
{
  for (size_t i = 0; i < bin_len; i++)
  {
    char high = hex[i * 2];
    char low = hex[i * 2 + 1];
    uint8_t h, l;
    if (high >= '0' && high <= '9')
      h = high - '0';
    else
      h = toupper(high) - 'A' + 10;
    if (low >= '0' && low <= '9')
      l = low - '0';
    else
      l = toupper(low) - 'A' + 10;
    bin[i] = (h << 4) | l;
  }
}

bool validate_prov_token(String token)
{
  unsigned long now = millis() / 1000;
  LOG("Validating token, current time: %lu", now);

  uint8_t result[32];
  uint32_t time_slot = now / 300;

  br_hmac_key_context kc;
  br_hmac_context ctx;
  br_hmac_key_init(&kc, &br_sha256_vtable, masterPSK, 16);
  br_hmac_init(&ctx, &kc, 0);
  br_hmac_update(&ctx, &time_slot, sizeof(time_slot));
  br_hmac_out(&ctx, result);

  char hex_token[65];
  bin2hex(result, 32, hex_token);

  LOG("Generated token: %s", hex_token);
  bool valid = token.equals(hex_token);
  if (!valid)
    LOG("Invalid token received: %s", token.c_str());
  return valid;
}

#define LORA_FREQ 433.0
#define LORA_CS D8
#define LORA_RST D0
#define LORA_IRQ D2
#define PROV_TOKEN_TIMEOUT 300000
#define MAX_NODES 10
#define MAX_MSG_LEN 128
#define HMAC_LEN 32

Ticker wdt;
unsigned long last_loop = 0;

uint8_t crypto_buf[256];

struct Node
{
  char id[16];
  uint8_t psk[16];
  char location[32];
  char name[32];
  uint32_t counter;
  uint32_t last_counter;
  unsigned long last_seen;
  uint8_t status;
  int8_t servo;
};

Node nodes[MAX_NODES];
uint8_t node_count = 0;

RH_RF95 lora(LORA_CS, LORA_IRQ);

ESP8266WebServer server(80);

WiFiManager wifiManager;

void configModeCallback(WiFiManager *myWiFiManager)
{
  Serial.println("Entered config mode");
  Serial.println(WiFi.softAPIP());
}

void saveConfigCallback()
{
  Serial.println("Should save config");
}

static size_t encrypt(uint8_t *output, const uint8_t *input, size_t len, const uint8_t *key)
{
  br_aes_big_cbcenc_keys ctx;
  uint8_t iv[16];

  br_hmac_drbg_generate(&rng_ctx, iv, sizeof(iv));
  memcpy(output, iv, 16);

  size_t padded_len = ((len + 15) / 16) * 16;
  uint8_t pad_value = padded_len - len;
  memset(crypto_buf, pad_value, padded_len);
  memcpy(crypto_buf, input, len);

  br_aes_big_cbcenc_init(&ctx, key, 16);
  br_aes_big_cbcenc_run(&ctx, iv, crypto_buf, padded_len);
  memcpy(output + 16, crypto_buf, padded_len);

  return padded_len + 16;
}

static bool decrypt(uint8_t *output, const uint8_t *input, size_t len, const uint8_t *key)
{
  if (len < 16 || ((len - 16) % 16 != 0))
    return false;

  br_aes_big_cbcdec_keys ctx;
  uint8_t iv[16];
  memcpy(iv, input, 16);

  br_aes_big_cbcdec_init(&ctx, key, 16);
  br_aes_big_cbcdec_run(&ctx, iv, const_cast<uint8_t *>(input + 16), len - 16);

  size_t pad_value = input[len - 1];
  if (pad_value > 16)
    return false;
  size_t plain_len = len - 16 - pad_value;
  memcpy(output, input + 16, plain_len);

  return true;
}

bool verify_hmac(const uint8_t *data, size_t len, const uint8_t *key, const uint8_t *hmac)
{
  br_hmac_key_context kc;
  br_hmac_context ctx;
  uint8_t result[32];

  br_hmac_key_init(&kc, &br_sha256_vtable, key, 16);
  br_hmac_init(&ctx, &kc, 0);
  br_hmac_update(&ctx, data, len);
  br_hmac_out(&ctx, result);

  return memcmp(result, hmac, 32) == 0;
}

void save_nodes()
{
  File file = LittleFS.open("/nodes", "w");
  if (!file)
    return;

  for (uint8_t i = 0; i < node_count; i++)
  {
    file.write((uint8_t *)&nodes[i], sizeof(Node));
  }
  file.close();
}

void load_nodes()
{
  File file = LittleFS.open("/nodes", "r");
  if (!file)
    return;

  node_count = 0;
  while (file.available() && node_count < MAX_NODES)
  {
    file.readBytes((char *)&nodes[node_count], sizeof(Node));
    node_count++;
  }
  file.close();
}

void send_lora(const uint8_t *data, size_t len, const uint8_t *key)
{
  uint8_t encrypted[256];
  size_t total_len = encrypt(encrypted, data, len, key);
  lora.send(encrypted, total_len);

  lora.waitPacketSent();
}

void handle_provision()
{
  LOG("Provision request received");
  static uint32_t last_prov = 0;
  if (millis() - last_prov < 5000)
  {
    server.send(429, "text/plain", "Too Many Requests");
    return;
  }
  last_prov = millis();

  StaticJsonDocument<256> doc;
  if (deserializeJson(doc, server.arg("plain")) != DeserializationError::Ok)
  {
    server.send(400, "text/plain", "Invalid JSON");
    return;
  }

  if (!validate_prov_token(doc["token"].as<String>()))
  {
    server.send(403, "text/plain", "Invalid Token");
    return;
  }

  if (node_count >= MAX_NODES)
  {
    LOG("Node capacity reached");
    server.send(507, "text/plain", "Node Capacity Full");
    return;
  }

  Node node;

  br_hmac_drbg_generate(&rng_ctx, (void *)node.psk, sizeof(node.psk));

  uint32_t node_id_num;
  br_hmac_drbg_generate(&rng_ctx, (uint8_t *)&node_id_num, sizeof(node_id_num));
  snprintf(node.id, sizeof(node.id), "nano_%04x", node_id_num);

  strncpy(node.location, doc["location"] | "", sizeof(node.location) - 1);
  node.location[sizeof(node.location) - 1] = '\0';
  strncpy(node.name, doc["name"] | "", sizeof(node.name) - 1);
  node.name[sizeof(node.name) - 1] = '\0';

  node.counter = 0;
  node.last_counter = 0;
  node.last_seen = millis();
  node.status = 0;
  node.servo = 0;

  StaticJsonDocument<128> resp;
  resp["id"] = node.id;

  char hex_psk[33] = {0};
  bin2hex(node.psk, 16, hex_psk);
  resp["psk"] = hex_psk;

  size_t jsonLen = serializeJson(resp, crypto_buf, sizeof(crypto_buf));

  uint8_t encrypted[256];
  size_t encryptedLen = encrypt(encrypted, crypto_buf, jsonLen, masterPSK);

  memcpy(&nodes[node_count], &node, sizeof(Node));
  node_count++;
  save_nodes();

  server.send(200, "application/octet-stream", (const char *)encrypted, encryptedLen);

  LOG("Provisioned new node: %s (Location: %s)", node.id, node.location);
}

void handle_control()
{
  LOG("Control command received");

  uint8_t hmac[HMAC_LEN];
  hex2bin(server.header("X-HMAC").c_str(), hmac, HMAC_LEN);

  String payload = server.arg("plain");
  if (!verify_hmac((uint8_t *)payload.c_str(), payload.length(), masterPSK, hmac))
  {
    LOG("HMAC verification failed for payload: %s", payload.c_str());
    server.send(401, "text/plain", "HMAC Mismatch");
    return;
  }

  StaticJsonDocument<128> doc;
  if (deserializeJson(doc, payload) != DeserializationError::Ok)
  {
    server.send(400, "text/plain", "Invalid JSON");
    return;
  }

  const char *target = doc["id"];
  const char *action = doc["action"];
  if (strcmp(action, "open") != 0 && strcmp(action, "close") != 0)
  {
    server.send(400, "text/plain", "Invalid Action");
    return;
  }

  for (uint8_t i = 0; i < node_count; i++)
  {
    if (strcmp(nodes[i].id, target) == 0)
    {

      StaticJsonDocument<64> cmd;
      cmd["cmd"] = action;
      cmd["ctr"] = ++nodes[i].counter;

      size_t len = serializeJson(cmd, crypto_buf, sizeof(crypto_buf));
      send_lora(crypto_buf, len, nodes[i].psk);
      LOG("Sending %s command to node %s (Counter: %u)", action, target, nodes[i].counter);
      server.send(200, "text/plain", "Command Sent");
      return;
    }
  }
  server.send(404, "text/plain", "Node Not Found");
}

void setup()
{

  pinMode(D3, INPUT_PULLUP);
  pinMode(D4, OUTPUT);
  digitalWrite(D4, HIGH);

  pinMode(LORA_CS, OUTPUT);
  digitalWrite(LORA_CS, HIGH);

  Serial.begin(115200);
  LOG("Initializing system...");

  if (!LittleFS.begin())
  {
    Serial.println("LittleFS Mount Failed");
    ESP.restart();
  }

  WiFi.mode(WIFI_AP);
  WiFi.softAP("GateControllerAP");

  br_hmac_drbg_init(&rng_ctx, &br_sha256_vtable, masterPSK, sizeof(masterPSK));

  wifiManager.setAPCallback(configModeCallback);
  wifiManager.setSaveConfigCallback(saveConfigCallback);
  wifiManager.setDebugOutput(false);

  pinMode(LORA_RST, OUTPUT);
  digitalWrite(LORA_RST, LOW);
  delay(50);
  digitalWrite(LORA_RST, HIGH);
  delay(200);

  SPI.setFrequency(500000);

  if (!lora.init())
  {
    LOG("LoRa init failed! Check:");
    LOG("CS: D8, RST: D0, IRQ: D2");
    LOG("3.3V stable? Add capacitor!");
    while (1)
    {
      digitalWrite(LED_BUILTIN, !digitalRead(LED_BUILTIN));
      delay(200);
    }
  }

  lora.setFrequency(LORA_FREQ);
  lora.setTxPower(20, false);
  lora.setSpreadingFactor(7);
  lora.setSignalBandwidth(125000);
  lora.setCodingRate4(5);

  LOG("LoRa initialized at %.1f MHz", LORA_FREQ);

  server.on("/provision", HTTP_POST, handle_provision);
  server.on("/control", HTTP_POST, handle_control);
  server.begin();

  load_nodes();

  LOG("AP Mode Active! IP: %s", WiFi.softAPIP().toString().c_str());
}

void loop()
{

  server.handleClient();

  if (lora.available())
  {
    uint8_t buf[RH_RF95_MAX_MESSAGE_LEN];
    uint8_t len = sizeof(buf);

    if (lora.recv(buf, &len))
    {
      LOG("Received %d byte LoRa message", len);

      for (uint8_t i = 0; i < node_count; i++)
      {
        uint8_t decrypted[RH_RF95_MAX_MESSAGE_LEN];
        if (decrypt(decrypted, buf, len, nodes[i].psk))
        {
          LOG("Decrypted message from node %s: %s", nodes[i].id, decrypted);
          StaticJsonDocument<128> doc;
          DeserializationError error = deserializeJson(doc, decrypted);
          if (error == DeserializationError::Ok)
          {
            nodes[i].last_seen = millis();
            nodes[i].status = 1;

            uint32_t ctr = doc["ctr"] | 0;
            if (ctr <= nodes[i].last_counter)
              continue;
            nodes[i].last_counter = ctr;

            if (doc.containsKey("servo"))
            {
              nodes[i].servo = doc["servo"];
            }
          }
        }
      }
    }
  }

  for (uint8_t i = 0; i < node_count; i++)
  {
    if (millis() - nodes[i].last_seen > 120000)
    {
      nodes[i].status = 0;
    }
  }

  static unsigned long lastDiag = 0;
  if (millis() - lastDiag > 5000)
  {
    lastDiag = millis();

    LOG("GPIO States: D0=%d, D2=%d, D3=%d, D8=%d",
        digitalRead(D0), digitalRead(D2), digitalRead(D3), digitalRead(D8));

    LOG("LoRa Message Available: %s", lora.available() ? "YES" : "NO");
  }
}
