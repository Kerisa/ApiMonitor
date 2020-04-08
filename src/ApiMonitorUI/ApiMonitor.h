#pragma once

#include <string>
#include <vector>
#include "pipemessage.h"

struct ModuleInfoItem
{
    std::string mName;
    std::string mPath;
    intptr_t    mBase{ 0 };
    struct ApiEntry
    {
        std::string mName;
        std::string mForwardto;
        intptr_t    mVa{ 0 };
        bool        mIsForward{ false };
        bool        mIsDataExport{ false };
        bool        mIsHook{ false };
    };
    std::vector<ApiEntry> mApis;
};

struct ApiLogItem
{
    int          mIndex{ 0 };
    std::string  mModuleName;
    std::string  mApiName;
    std::wstring mModuleNameW;
    std::wstring mApiNameW;
    intptr_t     mCallFrom{ 0 };
    intptr_t     mRawArgs[3]{ 0,0,0 };
    intptr_t     mTimes{ 0 };
    int          mTid{ 0 };
};

class PipeController
{
public:
    typedef void (*Handler)(const uint8_t *readData, uint32_t readDataSize, uint8_t *writeData, uint32_t *writeDataSize, const uint32_t maxWriteBuffer, void* userData);

    CRITICAL_SECTION mPipeMsgCS;
    PipeDefine::msg::SetBreakCondition mSetBreakCondition;
    Handler mMsgHandler;
    void* mUserData{ nullptr };
    bool mConditionReady{ false };

    // debug
    long long outputdbgstr{ 0 };
    std::vector<ModuleInfoItem> mModuleApis;

    PipeController()
    {
        InitializeCriticalSection(&mPipeMsgCS);
    }

    ~PipeController()
    {
        DeleteCriticalSection(&mPipeMsgCS);
    }

    PipeDefine::msg::SetBreakCondition* Lock()
    {
        EnterCriticalSection(&mPipeMsgCS);
        return &mSetBreakCondition;
    }

    void UnLock()
    {
        LeaveCriticalSection(&mPipeMsgCS);
    }
};

class Monitor
{
public:
    int LoadFile(const std::wstring& filePath);

    void SetPipeHandler(PipeController* controller);


    bool mContinueOEP{ false };
    bool mStopMonitor{ false };
    PipeController* mControllerRef{ nullptr };

private:
};