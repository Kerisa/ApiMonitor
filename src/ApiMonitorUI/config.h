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
    void            UpdateApi(const CString& dllPath, const CString& apiName, Status s);
    void            UpdateApi(const std::string& dllPath, const std::string& apiName, Status s);
    Status          GetApiHookStatus(const std::string& dllPath, const std::string& apiName);
    size_t          GetModuleApiCountInConfig(const std::string& dllPath) const;
    bool            CheckDllApiMatch(ModuleInfoItem* mii) const;

    static DllFilterConfig* GetConfig();

private:
    struct ApiDetail
    {
        bool mHook{ true };
    };
    struct ModuleDetail
    {
        std::map<std::string, ApiDetail>    mApis;
    };


    std::map<std::string, ModuleDetail>     mModules;
    CString                                 mConfigPath;

    static DllFilterConfig* msConfig;
};