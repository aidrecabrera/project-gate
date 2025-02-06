#ifndef GATENODE_H
#define GATENODE_H

#include "CryptoStrategy.h"
#include "CommandHandler.h"
#include <Servo.h>

class GateNode {
public:
    GateNode(CryptoStrategy* crypto, CommandHandler* cmdHandler)
        : cryptoStrategy(crypto), commandHandler(cmdHandler) {}
        
    void initialize() {
        // Actual initialization code
        gate.attach(9);
    }
    
    void run() {
        checkCommands();
        sendHeartbeat();
    }
    
private:
    CryptoStrategy* cryptoStrategy;
    CommandHandler* commandHandler;
    Servo gate;
    
    void checkCommands();
    void sendHeartbeat();
};

#endif 