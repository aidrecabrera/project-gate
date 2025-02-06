#ifndef EVENT_MANAGER_H
#define EVENT_MANAGER_H

#include <functional>
#include <map>
#include <Arduino.h>
#include <ArduinoJson.h>
#include <vector>

class EventManager {
public:
    using EventHandler = std::function<void(const ArduinoJson::JsonObject&)>;

    void subscribe(const ::String& eventType, EventHandler handler) {
        subscribers[eventType].push_back(handler);
    }

    void publish(const ::String& eventType, const ArduinoJson::JsonObject& data) {
        if (subscribers.find(eventType) != subscribers.end()) {
            for (auto& handler : subscribers[eventType]) {
                handler(data);
            }
        }
    }

private:
    std::map<::String, std::vector<EventHandler>> subscribers;
};

#endif 