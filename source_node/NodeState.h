#ifndef NODE_STATE_H
#define NODE_STATE_H

#include <Arduino.h>

class NodeState {
public:
    virtual ~NodeState() = default;
    virtual void enterState() = 0;
    virtual void process() = 0;
    virtual void exitState() = 0;
};

class ProvisioningState : public NodeState {
public:
    void enterState() override;
    void process() override;
    void exitState() override;
};

class OperationalState : public NodeState {
public:
    void enterState() override;
    void process() override;
    void exitState() override;
};

#endif 