#ifndef AES128CBCSTRATEGY_H
#define AES128CBCSTRATEGY_H

#include "CryptoStrategy.h"
#include <AESLib.h>

class AES128CBCStrategy : public CryptoStrategy {
public:
    size_t encrypt(uint8_t* output, const uint8_t* input, size_t len, const uint8_t* key) override {
        AESLib aes;
        uint8_t iv[16] = {0};
        aes.set_paddingmode(paddingMode::CMS);
        return aes.encrypt(input, len, output, key, 16, iv);
    }
    
    bool decrypt(uint8_t* output, const uint8_t* input, size_t len, const uint8_t* key) override {
        AESLib aes;
        uint8_t iv[16] = {0};
        aes.set_paddingmode(paddingMode::CMS);
        size_t decrypted = aes.decrypt((byte*)input, len, output, (byte*)key, 16, iv);
        return decrypted > 0;
    }
};

#endif 