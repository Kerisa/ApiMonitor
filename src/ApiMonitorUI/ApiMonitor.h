#pragma once

#include <functional>
#include <string>
#include <vector>
#include "pipemessage.h"

struct ModuleInfoItem;
struct ApiInfoItem;
struct SetBreakConditionUI : public PipeDefine::msg::SetBreakCondition
{
    ApiInfoItem*    mBelongApi{ nullptr };

    bool operator<(const SetBreakConditionUI& rhs) const
    {
        return this->func_addr < rhs.func_addr;
    }
};

struct ApiInfoItem
{
    std::string          mName;
    std::string          mForwardto;
    intptr_t             mVa{ 0 };
    bool                 mIsForward{ false };
    bool                 mIsDataExport{ false };
    bool                 mIsHook{ false };
    SetBreakConditionUI  mBp;
    ModuleInfoItem*      mBelongModule{ nullptr };  // Ç³¿½±´

    ApiInfoItem(ModuleInfoItem* ref)
    {
        mBp.mBelongApi = this;
        mBelongModule = ref;
    }

    bool        IsBpSet() const;
    void        BreakAlways();
    void        BreakNextTime();
    void        BreakOnTime(int time);
    void        RemoveBp();
    std::string GetBpDescription() const;
};

struct ModuleInfoItem
{
    std::string                 mName;
    std::string                 mPath;
    intptr_t                    mBase{ 0 };
    std::vector<ApiInfoItem*>   mApis;

    static void FromIpcMessage(ModuleInfoItem* mii, const PipeDefine::msg::ModuleApis& m);
    static void ToIpcFilter(const ModuleInfoItem* mii, PipeDefine::msg::ApiFilter& filter);
    static void Free(ModuleInfoItem* p) { delete p; }

private:
    ~ModuleInfoItem();
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

    Handler mMsgHandler;
    void* mUserData{ nullptr };
};

class Monitor
{
public:
    int LoadFile(const std::wstring& filePath, const std::wstring runParameters);

    void SetPipeHandler(PipeController* controller);
    bool SuspendProcess();
    bool ResumeProcess();

    std::function<void(ModuleInfoItem* mii)> f_SetupNtdllFilter;
    bool mContinueOEP{ false };
    bool mStopMonitor{ false };
    PipeController* mControllerRef{ nullptr };

private:
    PROCESS_INFORMATION mProcessInfo;
};