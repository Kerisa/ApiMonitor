
#include <atomic>
#include <array>
#include <cassert>
#include <exception>
#include <thread>
#include <vector>
#include "NamedPipe.h"

#include <windows.h>

using namespace std;

namespace Detail
{
    typedef struct
    {
        static constexpr int WRITE_BUFSIZE = 1024*1024;
        static constexpr int READ_BUFSIZE  = 8*1024*1024;

        OVERLAPPED  oOverlap;
        HANDLE      hPipeInst;
        bool        Released;
        std::array<uint8_t, READ_BUFSIZE>  chRequest;
        uint32_t    cbRead;
        std::array<uint8_t, WRITE_BUFSIZE> chReply;
        uint32_t    cbToWrite;
        void*       pUserData;
        NamedPipeServer::ReplayFuncType SetWriteMsg;

    } PIPEINST, *LPPIPEINST;


    void ThrowErorr(const char *base, int errId)
    {
        // base + FormatMessage(errId)
        throw;
    }

    VOID DisconnectAndClose(LPPIPEINST lpPipeInst)
    {
        if (!DisconnectNamedPipe(lpPipeInst->hPipeInst))
        {
            printf("DisconnectNamedPipe failed with %d.\n", GetLastError());
        }

        CloseHandle(lpPipeInst->hPipeInst);
        lpPipeInst->hPipeInst = NULL;
        lpPipeInst->Released = true;
        //if (lpPipeInst != NULL)
        //{
        //  GlobalFree(lpPipeInst);
        //}

        printf("Pipe %d Disconnected.\n", (int)lpPipeInst->hPipeInst);
    }

    VOID WINAPI ServerCompletedReadRoutine(DWORD dwErr, DWORD cbBytesRead, LPOVERLAPPED lpOverLap);
    VOID WINAPI ServerCompletedWriteRoutine(DWORD dwErr, DWORD cbWritten, LPOVERLAPPED lpOverLap)
    {
        BOOL fRead = FALSE;
        LPPIPEINST lpPipeInst = reinterpret_cast<LPPIPEINST>(lpOverLap);
        assert((dwErr == 0) && (cbWritten == lpPipeInst->cbToWrite));
        if ((dwErr == 0) && (cbWritten == lpPipeInst->cbToWrite))
        {
            fRead = ReadFileEx(
                lpPipeInst->hPipeInst,
                lpPipeInst->chRequest.data(),
                lpPipeInst->chRequest.size(),
                (LPOVERLAPPED)lpPipeInst,
                (LPOVERLAPPED_COMPLETION_ROUTINE)ServerCompletedReadRoutine
            );
        }

        if (!fRead)
            DisconnectAndClose(lpPipeInst);
    }


    VOID WINAPI ServerCompletedReadRoutine(DWORD dwErr, DWORD cbBytesRead, LPOVERLAPPED lpOverLap)
    {
        BOOL fWrite = FALSE;
        LPPIPEINST lpPipeInst = reinterpret_cast<LPPIPEINST>(lpOverLap);

        if ((dwErr == 0) && (cbBytesRead != 0))
        {
            // 默认为 0
            lpPipeInst->cbToWrite = 0;

            lpPipeInst->SetWriteMsg(
                lpPipeInst->chRequest.data(),
                cbBytesRead,
                lpPipeInst->chReply.data(),
                &lpPipeInst->cbToWrite,
                lpPipeInst->chReply.size(),
                lpPipeInst->pUserData
            );

            assert(lpPipeInst->cbToWrite < lpPipeInst->chReply.size());

            fWrite = WriteFileEx(
                lpPipeInst->hPipeInst,
                lpPipeInst->chReply.data(),
                lpPipeInst->cbToWrite,
                (LPOVERLAPPED)lpPipeInst,
                (LPOVERLAPPED_COMPLETION_ROUTINE)ServerCompletedWriteRoutine);
        }

        if (!fWrite)
            DisconnectAndClose(lpPipeInst);
    }


    struct ClientImplData {
        static constexpr int BUFSIZE = 4096 * 4;

        ClientImplData() {
            memset(&mSendOV, 0, sizeof(mSendOV));
            mReceiveData.resize(BUFSIZE);
        }

        OVERLAPPED mSendOV;
        HANDLE mPipe{ NULL };
        NamedPipeClient::ReplayFuncType mReplay;
        std::vector<uint8_t> mReceiveData;
    };

    VOID WINAPI ClientCompletedReadRoutine(DWORD dwErr, DWORD cbBytesRead, LPOVERLAPPED lpOverLap)
    {
        ClientImplData* lpPipeInst = reinterpret_cast<ClientImplData*>(lpOverLap);

        if ((dwErr == 0) && (cbBytesRead != 0))
        {
            if (lpPipeInst->mReplay)
                lpPipeInst->mReplay(lpPipeInst->mReceiveData.data(), cbBytesRead);
        }
    }

    VOID WINAPI ClientCompletedWriteRoutine(DWORD dwErr, DWORD cbWritten, LPOVERLAPPED lpOverLap)
    {
        BOOL fRead = FALSE;
        ClientImplData* lpPipeInst = reinterpret_cast<ClientImplData*>(lpOverLap);

        if (dwErr == 0)
        {
            fRead = ReadFileEx(
                lpPipeInst->mPipe,
                lpPipeInst->mReceiveData.data(),
                ClientImplData::BUFSIZE,
                (LPOVERLAPPED)lpPipeInst,
                (LPOVERLAPPED_COMPLETION_ROUTINE)ClientCompletedReadRoutine
            );
        }
    }
}

class NamedPipeServer::NamedPipeServerImpl
{
    static constexpr int PIPE_TIMEOUT = 5000;

public:
    NamedPipeServerImpl();
    ~NamedPipeServerImpl();

    void StartServer(const std::string & name, ReplayFuncType reply, void* userData, bool messageModePipe, bool writeThrough);
    void StopServer();
    bool IsRunning();

private:
    bool CreateAndConnectInstance(HANDLE *pipe, LPOVERLAPPED ov);

    std::string mPipeName;
    bool mMessageModePipe{ false };
    ReplayFuncType mReplayRoutine;
    std::vector<Detail::LPPIPEINST> mPipeGroup;
    std::atomic<bool> mStop{ true };
    HANDLE mExitEvent{ NULL };
};


NamedPipeServer::NamedPipeServerImpl::NamedPipeServerImpl()
{
}

NamedPipeServer::NamedPipeServerImpl::~NamedPipeServerImpl()
{
    StopServer();
}

bool NamedPipeServer::NamedPipeServerImpl::CreateAndConnectInstance(HANDLE *pipe, LPOVERLAPPED ov)
{
    assert(pipe);

    *pipe = CreateNamedPipeA(
        mPipeName.c_str(),
        PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
        PIPE_WAIT | (mMessageModePipe ? (PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE) : (PIPE_TYPE_BYTE | PIPE_READMODE_BYTE)),
        PIPE_UNLIMITED_INSTANCES,
        Detail::PIPEINST::WRITE_BUFSIZE,
        Detail::PIPEINST::WRITE_BUFSIZE,
        PIPE_TIMEOUT,
        NULL
    );
    if (*pipe == INVALID_HANDLE_VALUE)
    {
        Detail::ThrowErorr("CreateNamedPipe failed with %d.\n", GetLastError());
    }


    bool pendingIO = false;
    BOOL fConnected = ConnectNamedPipe(*pipe, ov);
    if (fConnected)
    {
        Detail::ThrowErorr("ConnectNamedPipe failed with %d.\n", GetLastError());
    }

    switch (GetLastError())
    {
    case ERROR_IO_PENDING:
        pendingIO = true;
        break;

        // 已连接
    case ERROR_PIPE_CONNECTED:
        if (SetEvent(ov->hEvent))
            break;

    default:
        Detail::ThrowErorr("ConnectNamedPipe failed with %d.\n", GetLastError());
    }

    return pendingIO;
}

void NamedPipeServer::NamedPipeServerImpl::StartServer(const std::string & name, ReplayFuncType reply, void* userData, bool messageModePipe, bool writeThrough)
{
    assert(mExitEvent == NULL);
    mExitEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (mExitEvent == NULL)
        Detail::ThrowErorr("CreateEvent failed with %d.\n", GetLastError());

    //SetNamedPipeHandleState();
    mPipeName = name;
    mMessageModePipe = messageModePipe;
    mStop = false;


    HANDLE newPipe = NULL;

    HANDLE hConnectEvent;
    OVERLAPPED oConnect;
    Detail::LPPIPEINST lpPipeInst;
    DWORD dwWait, cbRet;
    BOOL fSuccess, fPendingIO;


    hConnectEvent = CreateEvent(NULL, TRUE, TRUE, NULL);
    if (hConnectEvent == NULL)
    {
        Detail::ThrowErorr("CreateEvent failed with %d.\n", GetLastError());
    }

    oConnect.hEvent = hConnectEvent;
    fPendingIO = CreateAndConnectInstance(&newPipe, &oConnect);
    while (!mStop)
    {
        dwWait = WaitForSingleObjectEx(hConnectEvent, 1000, TRUE);
        switch (dwWait)
        {
        case WAIT_OBJECT_0:
            if (fPendingIO)
            {
                fSuccess = GetOverlappedResult(newPipe, &oConnect, &cbRet, FALSE);
                if (!fSuccess)
                {
                    Detail::ThrowErorr("ConnectNamedPipe (%d)\n", GetLastError());
                }
            }

            printf("pipe %d connected.\n", (int)newPipe);

            lpPipeInst = (Detail::LPPIPEINST)GlobalAlloc(GPTR, sizeof(Detail::PIPEINST));
            if (lpPipeInst == NULL)
            {
                Detail::ThrowErorr("GlobalAlloc failed (%d)\n", GetLastError());
            }

            mPipeGroup.push_back(lpPipeInst);
            // 初始化等待
            lpPipeInst->hPipeInst = newPipe;
            lpPipeInst->cbToWrite = 0;
            lpPipeInst->Released = false;
            lpPipeInst->SetWriteMsg = ReplayFuncType(reply);
            lpPipeInst->pUserData = userData;
            Detail::ServerCompletedWriteRoutine(0, 0, (LPOVERLAPPED)lpPipeInst);

            // 创建新的管道并等待新的客户端连接
            newPipe = NULL;
            fPendingIO = CreateAndConnectInstance(&newPipe, &oConnect);
            break;

        case WAIT_IO_COMPLETION:
            // 由完成例程触发，不操作
            break;

        case WAIT_TIMEOUT:
            // 用于退出检测
            break;

        default:
            Detail::ThrowErorr("WaitForSingleObjectEx (%d)\n", GetLastError());
        }
    }

    CancelIoEx(newPipe, &oConnect);
    CloseHandle(hConnectEvent);
    CloseHandle(newPipe);
    SetEvent(mExitEvent);
    return;
}

void NamedPipeServer::NamedPipeServerImpl::StopServer()
{
    mStop = true;

    if (mExitEvent != NULL)
    {
        WaitForSingleObject(mExitEvent, INFINITE);
        CloseHandle(mExitEvent);
        mExitEvent = NULL;
    }

    for (auto inst : mPipeGroup)
    {
        assert(inst);
        if (!inst->Released)
            DisconnectAndClose(inst);

        GlobalFree(inst);
    }

    mPipeGroup.clear();
}

bool NamedPipeServer::NamedPipeServerImpl::IsRunning()
{
    return !mStop;
}


NamedPipeServer::NamedPipeServer()
{
    mImpl = new NamedPipeServerImpl();
}

NamedPipeServer::~NamedPipeServer()
{
    delete mImpl;
}

void NamedPipeServer::StartServer(const std::string & name, ReplayFuncType reply, void* userData, bool messageModePipe, bool writeThrough)
{
    mImpl->StartServer(name, reply, userData, messageModePipe, writeThrough);
}

bool NamedPipeServer::IsRunning()
{
    return mImpl->IsRunning();
}

bool NamedPipeServer::StopServer()
{
    mImpl->StopServer();
    return false;
}



////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////



class NamedPipeClient::NamedPipeClientImpl
{
public:
    NamedPipeClientImpl();
    ~NamedPipeClientImpl();

    bool ConnectPipe(const std::string & name, uint32_t waitTime);
    bool Disconnect();
    bool Send(void *data, uint32_t sizeInByte);
    void SetReceiver(ReplayFuncType replay);
    void WaitReply();

    Detail::ClientImplData mData;
    std::string mPipeName;
    std::thread mWaitThread;
    HANDLE mExitEvent{ NULL };
    std::atomic<bool> mStop{ true };
};

NamedPipeClient::NamedPipeClientImpl::NamedPipeClientImpl()
{
    mExitEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    mWaitThread = std::thread(&NamedPipeClientImpl::WaitReply, this);
}

NamedPipeClient::NamedPipeClientImpl::~NamedPipeClientImpl()
{
    Disconnect();
    CloseHandle(mExitEvent);
    mWaitThread.join();
}

bool NamedPipeClient::NamedPipeClientImpl::ConnectPipe(const std::string & name, uint32_t waitTime)
{
    int busyRetry = 5;

    if (!mStop)
        return false;

    assert(mData.mPipe == NULL || mData.mPipe == INVALID_HANDLE_VALUE);

    while (busyRetry--)
    {
        mData.mPipe = CreateFileA(name.c_str(), GENERIC_READ | GENERIC_WRITE,
            0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL
        );
        if (mData.mPipe != INVALID_HANDLE_VALUE)
            break;

        if (GetLastError() != ERROR_PIPE_BUSY)
        {
            printf("Could not open pipe. GLE=%d\n", GetLastError());
            return false;
        }

        if (!WaitNamedPipeA(name.c_str(), waitTime))
        {
            printf("Could not open pipe: 20 second wait timed out.");
            return false;
        }
    }

    DWORD dwMode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(mData.mPipe, &dwMode, NULL, NULL))
    {
        Disconnect();
        Detail::ThrowErorr("SetNamedPipeHandleState failed. GLE=%d\n", GetLastError());
        return false;
    }

    static_assert(offsetof(Detail::ClientImplData, mSendOV) == 0, "OVERLAPPED should be first member");
    memset(&mData.mSendOV, 0, sizeof(mData.mSendOV));
    mStop = false;
    mPipeName = name;
    return true;
}

bool NamedPipeClient::NamedPipeClientImpl::Disconnect()
{
    mStop = true;
    if (mData.mPipe != NULL && mData.mPipe != INVALID_HANDLE_VALUE)
    {
        CancelIoEx(mData.mPipe, &mData.mSendOV);
        CloseHandle(mData.mPipe);
        mData.mPipe = NULL;
    }
    mPipeName.clear();
    return true;
}

bool NamedPipeClient::NamedPipeClientImpl::Send(void *data, uint32_t sizeInByte)
{
    if (mStop)
        return false;

    assert(mData.mPipe != NULL && mData.mPipe != INVALID_HANDLE_VALUE);
    DWORD dummy = 0;
    BOOL ret = WriteFile(mData.mPipe, data, sizeInByte, &dummy, reinterpret_cast<LPOVERLAPPED>(&mData));
    return !!ret;
}

void NamedPipeClient::NamedPipeClientImpl::SetReceiver(ReplayFuncType replay)
{
    mData.mReplay = replay;
}

void NamedPipeClient::NamedPipeClientImpl::WaitReply()
{
    bool readFinish = true;
    while (true)
    {
        if (!mStop && readFinish)
        {
            BOOL ret = ReadFileEx(
                mData.mPipe,
                mData.mReceiveData.data(),
                mData.mReceiveData.size(),
                &mData.mSendOV,
                Detail::ClientCompletedReadRoutine
            );
            if (!ret)
            {
                Disconnect();
                continue;
            }
            readFinish = false;
        }

        DWORD wait = WaitForSingleObjectEx(mExitEvent, 1000, TRUE);
        switch (wait)
        {
        case WAIT_IO_COMPLETION:
            readFinish = true;
            break;

        case WAIT_TIMEOUT:
            break;

        case WAIT_OBJECT_0:
            return;

        default:
            Detail::ThrowErorr("WaitReply error", wait);
        }
    }
}



////////////////////////////////////////////////////////////////////////////////



NamedPipeClient::NamedPipeClient()
{
    mImpl = new NamedPipeClientImpl();
}

NamedPipeClient::~NamedPipeClient()
{
    delete mImpl;
}

bool NamedPipeClient::ConnectPipe(const std::string & name, uint32_t waitTime)
{
    return mImpl->ConnectPipe(name, waitTime);
}

bool NamedPipeClient::Disconnect()
{
    return mImpl->Disconnect();
}

void NamedPipeClient::SetReceiver(ReplayFuncType replay)
{
    mImpl->SetReceiver(replay);
}

bool NamedPipeClient::Send(void *data, uint32_t sizeInByte)
{
    return mImpl->Send(data, sizeInByte);
}