#ifndef COMMAND_HANDLER_H
#define COMMAND_HANDLER_H

#include <Arduino.h>
#include <ArduinoJson.h>

class Command {
public:
    virtual ~Command() = default;
    virtual void execute() = 0;
};

class CommandHandler {
public:
    virtual ~CommandHandler() = default;
    virtual void handleCommand(const String& command, const ArduinoJson::JsonObject& params) = 0;
};

#endif // COMMAND_HANDLER_H
