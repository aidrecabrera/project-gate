#ifndef LORA_OBSERVER_H
#define LORA_OBSERVER_H

#include <Arduino.h>

class LoRaObserver {
public:
    virtual ~LoRaObserver() = default;
    virtual void onMessageReceived(const uint8_t* payload, size_t length) = 0;
    virtual void onMessageSent(bool success) = 0;
};

#endif 