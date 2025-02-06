#ifndef HELPER_H
#define HELPER_H

#include <Arduino.h>

void bin2hex(uint8_t* bin, size_t len, char* hex);
void hex2bin(const char* hex, uint8_t* bin, size_t len);
bool validate_prov_token(const String &token);

#endif