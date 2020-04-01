#pragma once

#include <functional>
#include <string>


class NamedPipeServer
{
    class NamedPipeServerImpl;

public:
    // Writes to "writeData" directly if need reply, buffer up to "maxWriteBuffer" bytes
    typedef std::function<void(const uint8_t *readData, uint32_t readDataSize, uint8_t *writeData, uint32_t *writeDataSize, const uint32_t maxWriteBuffer)> ReplayFuncType;

    NamedPipeServer();
    ~NamedPipeServer();

    void StartServer(const std::string &name, ReplayFuncType reply, bool writeThrough = false);
    bool IsRunning();
    bool StopServer();

private:
    NamedPipeServerImpl *mImpl{ nullptr };
};



class NamedPipeClient
{
    class NamedPipeClientImpl;

public:
    typedef std::function<void(const uint8_t *replayData, uint32_t dataSize)> ReplayFuncType;

    NamedPipeClient();
    ~NamedPipeClient();

    bool ConnectPipe(const std::string &name, uint32_t waitTime = 5000);
    bool Disconnect();
    void SetReceiver(ReplayFuncType replay);
    bool Send(void *data, uint32_t sizeInByte);

private:
    NamedPipeClientImpl *mImpl{ nullptr };
};