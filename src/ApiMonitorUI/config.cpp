
#include "stdafx.h"
#include <fstream>
#include <string>
#include "json/json.h"
#include "config.h"
#include "uihelper.h"

using namespace std;


DllFilterConfig* DllFilterConfig::msConfig;

const CString& DllFilterConfig::GetConfigPath()
{
    if (mConfigPath.IsEmpty())
    {
        TCHAR buffer[512];
        GetModuleFileName(0, buffer, sizeof(buffer));
        CString selfPath = buffer;
        CString selfDir = selfPath.Mid(0, selfPath.ReverseFind(_T('\\')));
        mConfigPath = selfDir + _T("\\config.json");
    }
    return mConfigPath;
}

CString DllFilterConfig::GetConfigDir()
{
    const CString& p = GetConfigPath();
    return p.Mid(0, p.ReverseFind(_T('\\')));
}

bool DllFilterConfig::LoadFromFile()
{
    ifstream f(ToStdString(GetConfigPath()), ios::binary);
    if (!f.is_open())
        return false;
    f.seekg(0, ios::end);
    vector<char> data(f.tellg());
    if (data.size() == 0)
        return false;
    f.seekg(0, ios::beg);
    f.read(data.data(), data.size());
    f.close();

    Json::Value root;
    Json::Reader reader;
    if (!reader.parse(data.data(), root))
        return false;

    mModules.clear();
    for (Json::ArrayIndex i = 0; i < root.size(); ++i)
    {
        Json::Value& e = root[i];
        string dllPath = e["Path"].asCString();

        ModuleDetail md;
        Json::Value& jApi = e["Api"];
        for (Json::ArrayIndex k = 0; k < jApi.size(); ++k)
        {
            string apiName = jApi[k]["Name"].asCString();
            ApiDetail ad;
            ad.mHook = jApi[k]["Hook"].asBool();
            auto result = md.mApis.insert(make_pair(apiName, ad));
            if (!result.second)
                throw "duplicate api name";
        }
        
        auto result = mModules.insert(make_pair(dllPath, md));
        if (!result.second)
            throw "duplicate module path";
    }
    return true;
}

void DllFilterConfig::SaveToFile()
{
    Json::Value root;
    for (auto it = mModules.begin(); it != mModules.end(); ++it)
    {
        Json::Value module;
        module["Path"] = it->first;
        Json::Value apis;
        for (auto itt = it->second.mApis.begin(); itt != it->second.mApis.end(); ++itt)
        {
            Json::Value detail;
            detail["Name"] = itt->first;
            detail["Hook"] = itt->second.mHook;
            apis.append(detail);
        }
        module["Api"] = apis;
        root.append(module);
    }

    Json::FastWriter writer;
    string s = writer.write(root);
    ofstream f(ToStdString(GetConfigPath()), ios::binary);
    f.write(s.c_str(), s.size());
    f.close();
}

void DllFilterConfig::UpdateApi(const CString & _dllPath, const CString & _apiName, Status s)
{
    string dllName = ToStdString(_dllPath);
    string apiName = ToStdString(_apiName);
    UpdateApi(dllName, apiName, s);
}

void DllFilterConfig::UpdateApi(const std::string & dllPath, const std::string & apiName, Status s)
{
    if (s != kHook && s != kIgnore)
        throw "invalid status";

    auto p = dllPath;
    for (auto& c : p)
        c = tolower(c);

    auto& mDetail = mModules[p];
    auto& aDetail = mDetail.mApis[apiName];
    aDetail.mHook = s == kHook;
}

DllFilterConfig::Status DllFilterConfig::GetApiHookStatus(const std::string& dllPath, const std::string& apiName)
{
    auto p = dllPath;
    for (auto& c : p)
        c = tolower(c);

    auto it = mModules.find(p);
    if (it == mModules.end())
        return kNotDefine;
    auto itt = it->second.mApis.find(apiName);
    if (itt == it->second.mApis.end())
        return kNotDefine;
    return itt->second.mHook ? kHook : kIgnore;
}

size_t DllFilterConfig::GetModuleApiCountInConfig(const std::string & dllPath) const
{
    auto p = dllPath;
    for (auto& c : p)
        c = tolower(c);
    auto it = mModules.find(p);
    if (it == mModules.end())
        return 0;
    return it->second.mApis.size();
}

bool DllFilterConfig::CheckDllApiMatch(ModuleInfoItem * mii) const
{
    if (!mii)
        return false;

    // 配置中保存同名 dll 导出函数的并集，所以至少大于等于目标 dll 的导出函数数量

    if (GetModuleApiCountInConfig(mii->mPath) < mii->mApis.size())
        return false;

    for (size_t i = 0; i < mii->mApis.size(); ++i)
    {
        auto s = DllFilterConfig::GetConfig()->GetApiHookStatus(mii->mPath, mii->mApis[i]->mName);
        if (s != DllFilterConfig::kHook && s != DllFilterConfig::kIgnore)
        {
            return false;
        }
    }
}

DllFilterConfig * DllFilterConfig::GetConfig()
{
    if (!msConfig)
        msConfig = new DllFilterConfig();
    return msConfig;
}
