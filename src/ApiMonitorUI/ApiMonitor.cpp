
#include <cassert>
#include <iostream>
#include <sstream>
#include <thread>
#include <vector>
#include <windows.h>
#include "def.h"
#include "NamedPipe.h"
#include "pipemessage.h"
#include "ApiMonitor.h"
#include "hookroutine.h"

using namespace std;


void Monitor::SetPipeHandler(PipeController * controller)
{
    mControllerRef = controller;
}

bool Monitor::SuspendProcess()
{
    auto sus = (FN_NtSuspendProcess)GetProcAddress((HMODULE)GetModuleHandleA("ntdll.dll"), "NtSuspendProcess");
    if (!sus)
        return false;

    LONG ret = sus(mProcessInfo.hProcess);
    return ret >= 0;
}

bool Monitor::ResumeProcess()
{
    auto res = (FN_NtSuspendProcess)GetProcAddress((HMODULE)GetModuleHandleA("ntdll.dll"), "NtResumeProcess");
    if (!res)
        return false;

    LONG ret = res(mProcessInfo.hProcess);
    return ret >= 0;
}

int Monitor::LoadFile(const std::wstring& filePath, const std::wstring runParameters)
{
    if (filePath.empty())
        return -1;

    std::wstring pathWithQuota = filePath;
    if (!filePath.empty() && filePath.front() != L'\"' && filePath.back() != L'\"' && filePath.find(L" ") != std::wstring::npos)
        pathWithQuota = L"\"" + filePath + L"\"";

    WCHAR cmd[MAX_PATH] = { 0 };
    wcscpy_s(cmd, pathWithQuota.c_str());

    STARTUPINFO si = { 0 };
    si.cb = sizeof(si);
    memset(&mProcessInfo, 0, sizeof(mProcessInfo));
    BOOL success = CreateProcess(filePath.c_str(), cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &mProcessInfo);
    if (!success)
    {
        assert(0);
        return -1;
    }

    LPVOID paramBase = VirtualAllocEx(mProcessInfo.hProcess, (LPVOID)PARAM::PARAM_ADDR, sizeof(PARAM), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    assert(paramBase);
    if (!paramBase)
    {
        CloseHandle(mProcessInfo.hProcess);
        CloseHandle(mProcessInfo.hThread);
        return -1;
    }

    SIZE_T R = 0;
    PARAM param;
    memset(&param, 0, sizeof(PARAM));
    param.ntdllBase = (LPVOID)GetModuleHandleA("ntdll.dll");
    param.f_LdrLoadDll = (FN_LdrLoadDll)((ULONG_PTR)GetProcAddress((HMODULE)param.ntdllBase, "LdrLoadDll") + 2);
    param.dwProcessId = mProcessInfo.dwProcessId;
    param.dwThreadId = mProcessInfo.dwThreadId;
    param.ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(mProcessInfo.hThread, &param.ctx);

    assert(f_SetupNtdllFilter);
    PipeDefine::msg::ModuleApis msgModuleApis;
    CollectModuleInfo((HMODULE)param.ntdllBase, "ntdll.dll", GetDllNameFromExportDirectory((HMODULE)param.ntdllBase), msgModuleApis);
    ModuleInfoItem* mii = new ModuleInfoItem();
    ModuleInfoItem::FromIpcMessage(mii, msgModuleApis);
    f_SetupNtdllFilter(mii);
    PipeDefine::msg::ApiFilter filter;
    ModuleInfoItem::ToIpcFilter(mii, filter);
    std::vector<char> v = filter.Serial();
    assert(v.size() < sizeof(param.ntdllFilterSerialData));
    memcpy_s(param.ntdllFilterSerialData, sizeof(param.ntdllFilterSerialData), v.data(), v.size());
    param.ntdllFilterSerialDataSize = v.size();

    char bytesOfNtMapViewOfSectionPad[32] = { 0 };
    ReadProcessMemory(mProcessInfo.hProcess, (LPVOID)GetProcAddress((HMODULE)param.ntdllBase, "NtMapViewOfSection"), bytesOfNtMapViewOfSectionPad, sizeof(bytesOfNtMapViewOfSectionPad), &R);
    assert(bytesOfNtMapViewOfSectionPad[0] == '\xb8');  // mov eax,28h
    param.NtMapViewOfSectionServerId = *(PDWORD)&bytesOfNtMapViewOfSectionPad[1];
    assert(bytesOfNtMapViewOfSectionPad[5] == '\xba');  // mov edx,offset XXX
    param.f_Wow64SystemServiceCall = (LPVOID)*(PDWORD)&bytesOfNtMapViewOfSectionPad[6];
    assert(*(PWORD)&bytesOfNtMapViewOfSectionPad[10] == 0xd2ff);  // call edx
    assert(param.f_Wow64SystemServiceCall != 0);
    PVOID oep = BuildRemoteData(mProcessInfo.hProcess, TEXT("C:\\Projects\\ApiMonitor\\bin\\Win32\\Release\\PayLoad.dll"));

    WriteProcessMemory(mProcessInfo.hProcess, paramBase, &param, sizeof(param), &R);
    CONTEXT copy = param.ctx;
    copy.Eax = (DWORD)oep;
    SetThreadContext(mProcessInfo.hThread, &copy);

    NamedPipeServer ps;
    std::thread th = std::thread([&]() {
        char piepeName[256] = { 0 };
        sprintf_s(piepeName, sizeof(piepeName), PipeDefine::PIPE_NAME_TEMPLATE, mProcessInfo.dwProcessId);
        ps.StartServer(piepeName, mControllerRef->mMsgHandler, mControllerRef->mUserData);
    });

    while (!ps.IsRunning())
        Sleep(1);
    ResumeThread(mProcessInfo.hThread);

    DWORD status = STATUS_TIMEOUT;
    while (!mStopMonitor && status != WAIT_OBJECT_0)
    {
        status = WaitForSingleObject(mProcessInfo.hProcess, 1000);
    }
    
    CloseHandle(mProcessInfo.hProcess);
    CloseHandle(mProcessInfo.hThread);
    memset(&mProcessInfo, 0, sizeof(mProcessInfo));
    ps.StopServer();
    th.join();
    return 0;
}

bool ApiInfoItem::IsBpSet() const
{
    return mBp.flags != 0;
}

void ApiInfoItem::BreakAlways()
{
    RemoveBp();
    mBp.flags = PipeDefine::msg::SetBreakCondition::FLAG_BC_ALWAYS;
}

void ApiInfoItem::BreakNextTime()
{
    RemoveBp();
    mBp.flags = PipeDefine::msg::SetBreakCondition::FLAG_BC_NEXT_TIME;
}

void ApiInfoItem::BreakOnTime(int time)
{
    RemoveBp();
    mBp.flags = PipeDefine::msg::SetBreakCondition::FLAG_BC_INVOKE_TIME;
    mBp.invoke_time = time;
}

void ApiInfoItem::RemoveBp()
{
    mBp.flags = 0;
}

std::string ApiInfoItem::GetBpDescription() const
{
    assert(mBp.flags == 0 ||
        mBp.flags == PipeDefine::msg::SetBreakCondition::FLAG_BC_INVOKE_TIME ||
        mBp.flags == PipeDefine::msg::SetBreakCondition::FLAG_BC_NEXT_TIME ||
        mBp.flags == PipeDefine::msg::SetBreakCondition::FLAG_BC_ALWAYS);
    switch (mBp.flags)
    {
    case 0:
        return "";
    case PipeDefine::msg::SetBreakCondition::FLAG_BC_ALWAYS:
        return "Always";
    case PipeDefine::msg::SetBreakCondition::FLAG_BC_NEXT_TIME:
        return "Next Time";
    case PipeDefine::msg::SetBreakCondition::FLAG_BC_INVOKE_TIME: {
        std::stringstream ss;
        ss << mBp.invoke_time;
        return std::string("times == ") + ss.str();
    }
    default:
        assert(0);
        return "";
    }
}

ModuleInfoItem::~ModuleInfoItem()
{
    for (auto a : mApis)
        delete a;
}

void ModuleInfoItem::FromIpcMessage(ModuleInfoItem* mii, const PipeDefine::msg::ModuleApis & m)
{
    mii->mName = m.module_name;
    mii->mPath = m.module_path;
    mii->mBase = static_cast<intptr_t>(m.module_base);
    for (size_t i = 0; i < m.apis.size(); ++i)
    {
        mii->mApis.push_back(new ApiInfoItem(mii));
        ApiInfoItem* ae = mii->mApis.back();
        ae->mName = m.apis[i].name;
        ae->mVa = static_cast<intptr_t>(m.apis[i].va);
        ae->mIsForward = m.apis[i].forward_api;
        ae->mIsDataExport = m.apis[i].data_export;
        ae->mForwardto = m.apis[i].forwardto;
        ae->mBp.func_addr = ae->mVa;
    }
}

void ModuleInfoItem::ToIpcFilter(const ModuleInfoItem * mii, PipeDefine::msg::ApiFilter & filter)
{
    filter.module_name = mii->mName;
    for (size_t i = 0; i < mii->mApis.size(); ++i)
    {
        PipeDefine::msg::ApiFilter::Api filter_api;
        filter_api.flags = mii->mApis[i]->mBp.flags;
        if (mii->mApis[i]->mIsHook)
            filter_api.SetFilter();
        filter_api.call_from = mii->mApis[i]->mBp.call_from;
        filter_api.func_addr = mii->mApis[i]->mBp.func_addr;
        filter_api.invoke_time = mii->mApis[i]->mBp.invoke_time;
        assert(mii->mApis[i]->mVa == mii->mApis[i]->mBp.func_addr);

        filter.apis.push_back(filter_api);
    }
}
