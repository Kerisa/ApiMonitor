#pragma once

#include <afxstr.h>
#include <map>
#include <string>
#include "ApiMonitor.h"

class DllFilterConfig
{
public:
    enum Status
    {
        kNotDefine,
        kHook,
        kIgnore,
    };
    const CString&  GetConfigPath();
    CString         GetConfigDir();
    bool            LoadFromFile();
    void            SaveToFile();
    void            UpdateApi(ApiInfoItem* aii);
    void            UpdateApi(const CString& dllPath, const CString& apiName, Status s);
    void            UpdateApi(const std::string& dllPath, const std::string& apiName, Status s);
    Status          GetApiHookStatus(const std::string& dllPath, const std::string& apiName);
    bool            GetApiBpInfo(const std::string& dllPath, const std::string& apiName, PipeDefine::msg::SetBreakCondition& sbc);
    size_t          GetModuleApiCountInConfig(const std::string& dllPath) const;
    bool            CheckDllApiMatch(ModuleInfoItem* mii) const;

    static DllFilterConfig* GetConfig();

private:
    struct ApiDetail
    {
        static constexpr long FLAG_BC_ALWAYS        = 2;
        static constexpr long FLAG_BC_NEXT_TIME     = 4;
        static constexpr long FLAG_BC_CALL_FROM     = 8;
        static constexpr long FLAG_BC_INVOKE_TIME   = 16;
        uint32_t mBpFlag{ 0 };
        uint64_t mBpExtra{ 0 };
        bool     mHook{ true };
    };
    struct ModuleDetail
    {
        std::map<std::string, ApiDetail>    mApis;
    };


    std::map<std::string, ModuleDetail>     mModules;
    CString                                 mConfigPath;

    static DllFilterConfig* msConfig;
};