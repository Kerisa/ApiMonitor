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
    void            UpdateApi(const CString& dllName, const CString& apiName, Status s);
    Status          GetApiHookStatus(const CString& dllName, const CString& apiName);

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
};