#ifndef CRYPTO_STRATEGY_H
#define CRYPTO_STRATEGY_H

#include <Arduino.h>

class CryptoStrategy {
public:
    virtual ~CryptoStrategy() = default;
    virtual size_t encrypt(uint8_t* output, const uint8_t* input, size_t len, const uint8_t* key) = 0;
    virtual bool decrypt(uint8_t* output, const uint8_t* input, size_t len, const uint8_t* key) = 0;
};

#endif 