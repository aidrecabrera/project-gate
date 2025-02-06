#ifndef GATE_COMMANDS_H
#define GATE_COMMANDS_H

#include "CommandHandler.h"
#include <Servo.h>

class CommandProcessor : public CommandHandler {
public:
    CommandProcessor(Servo& gate);
    void handleCommand(const String& command, const ArduinoJson::JsonObject& params) override;

private:
    class OpenCommand : public Command {
    public:
        OpenCommand(Servo& gate) : gate(gate) {}
        void execute() override { gate.write(180); }
    private:
        Servo& gate;
    };

    class CloseCommand : public Command {
    public:
        CloseCommand(Servo& gate) : gate(gate) {}
        void execute() override { gate.write(0); }
    private:
        Servo& gate;
    };

    OpenCommand openCmd;
    CloseCommand closeCmd;
};

#endif 