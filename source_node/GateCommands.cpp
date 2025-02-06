#include "GateCommands.h"
#include <Servo.h>

CommandProcessor::CommandProcessor(Servo& gate) : 
    openCmd(gate), 
    closeCmd(gate) {
}

void CommandProcessor::handleCommand(const String& command, const ArduinoJson::JsonObject& params) {
    if (command == "open") {
        openCmd.execute();
    } else if (command == "close") {
        closeCmd.execute();
    }
} 