
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

using namespace std;


namespace Detail
{


typedef struct reloc_line
{
    WORD m_addr : 12;
    WORD m_type : 4;
} reloc_line;

void LoadVReloc(ULONG_PTR hBase, bool bForce, ULONG_PTR delta)
{
    PIMAGE_NT_HEADERS imNH = (PIMAGE_NT_HEADERS)(hBase + ((PIMAGE_DOS_HEADER)hBase)->e_lfanew);
    if (imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0)
        return; // 没有重定位数据
    if (hBase == imNH->OptionalHeader.ImageBase && bForce == FALSE)
        return; // 装入了默认地址
    if (delta == 0)
        delta = hBase - imNH->OptionalHeader.ImageBase;
    ULONG_PTR lpreloc = hBase + imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    PIMAGE_BASE_RELOCATION pimBR = (PIMAGE_BASE_RELOCATION)lpreloc;
    while (pimBR->VirtualAddress != 0)
    {
        reloc_line* reline = (reloc_line*)((char*)pimBR + sizeof(IMAGE_BASE_RELOCATION));
        int preNum = (pimBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(reloc_line);
        for (int i = 0; i < preNum; ++i)
        {
            switch (reline->m_type)
            {
            case IMAGE_REL_BASED_HIGHLOW:
                *(PDWORD)(hBase + pimBR->VirtualAddress + reline->m_addr) += delta;
                break;
            case IMAGE_REL_BASED_DIR64:
                *(ULONG_PTR*)(hBase + pimBR->VirtualAddress + reline->m_addr) += delta;
                break;
            }
            ++reline;
        }
        pimBR = (PIMAGE_BASE_RELOCATION)reline;
    }
}


PVOID BuildRemoteData(HANDLE hProcess, const TCHAR* dllPath)
{
    HMODULE hDll2 = LoadLibraryEx(dllPath, NULL, 0);
    ULONG_PTR entry = (ULONG_PTR)GetProcAddress(hDll2, "Entry");
    HANDLE hDll = CreateFile(dllPath, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hDll == INVALID_HANDLE_VALUE)
        return NULL;
    std::vector<char> file(GetFileSize(hDll, 0));
    SIZE_T R;
    ReadFile(hDll, file.data(), file.size(), &R, 0);
    CloseHandle(hDll);

    char* imageData = (char*)file.data();
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)(imageData + ((PIMAGE_DOS_HEADER)imageData)->e_lfanew);
    DWORD imageSize = ntHeader->OptionalHeader.SizeOfImage;
    std::vector<char> memData(imageSize);
    PIMAGE_SECTION_HEADER secHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)ntHeader + sizeof(IMAGE_NT_HEADERS));
    DWORD secHeaderBegin = secHeader->VirtualAddress;
    for (DWORD i = 0; i < ntHeader->FileHeader.NumberOfSections; ++i)
    {
        if (secHeader->PointerToRawData != 0)
            secHeaderBegin = min(secHeader->PointerToRawData, secHeaderBegin);
        memcpy(&memData[secHeader->VirtualAddress], imageData + secHeader->PointerToRawData, secHeader->SizeOfRawData);
        ++secHeader;
    }
    memcpy(memData.data(), imageData, secHeaderBegin); // 复制 pe 头
    PVOID newBase = VirtualAllocEx(hProcess, 0, imageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ULONG_PTR delta = (ULONG_PTR)newBase - (ULONG_PTR)ntHeader->OptionalHeader.ImageBase;
    if (delta != 0) // 需要重定位
        LoadVReloc((ULONG_PTR)memData.data(), TRUE, delta);
    SIZE_T W = 0;
    WriteProcessMemory(hProcess, newBase, memData.data(), imageSize, &W);
    PVOID oep = (PVOID)(entry - (ULONG_PTR)hDll2 + (ULONG_PTR)newBase);


    HMODULE ntDllBase = GetModuleHandleA("ntdll.dll");
    auto pLdrLoadDll = (FN_LdrLoadDll)GetProcAddress(ntDllBase, "LdrLoadDll");
    vector<unsigned char> remoteMemory(0x200);
    ReadProcessMemory(hProcess, (LPVOID)((ULONG_PTR)pLdrLoadDll - 0x100), remoteMemory.data(), remoteMemory.size(), &R);
    bool found = false;
    size_t position = 0;
    for (size_t i = 0x100; i > 0 && !found; --i)
    {
        if (remoteMemory[i] == 0xcc)
        {
            int k = 0;
            for (; k < 7; ++k)
                if (remoteMemory[i - k] != 0xcc)
                    break;
            if (k == 7)
            {
                found = true;
                position = i - 6;
            }
        }
    }
    assert(found);
    if (found)
    {
        char jmp[2];
        jmp[0] = '\xeb';
        jmp[1] = position - (0x100 + 0x2);
        WriteProcessMemory(hProcess, (LPVOID)pLdrLoadDll, jmp, sizeof(jmp), &R);

        auto hook = GetProcAddress(hDll2, "HookLdrLoadDllPad");
        char jmp2[6];
        jmp2[0] = '\x68';
        *(PDWORD)&jmp2[1] = (DWORD)((ULONG_PTR)hook - (ULONG_PTR)hDll2 + (ULONG_PTR)newBase);
        jmp2[5] = '\xc3';
        WriteProcessMemory(hProcess, (LPVOID)((ULONG_PTR)pLdrLoadDll - 0x100 + position), jmp2, sizeof(jmp2), &R);
    }


    ///////////////////////////////////////////////////////////////////////////
    // 拦截 NtMapViewOfSection
    {
        ULONG_PTR pNtMapViewOfSection = (ULONG_PTR)GetProcAddress(ntDllBase, "NtMapViewOfSection");
        auto hook = GetProcAddress(hDll2, "NtMapViewOfSectionPad");
        char jmp[6] = { 0 };
        jmp[0] = '\x68';
        *(PDWORD)&jmp[1] = (DWORD)((ULONG_PTR)hook - (ULONG_PTR)hDll2 + (ULONG_PTR)newBase);
        jmp[5] = '\xc3';
        WriteProcessMemory(hProcess, (LPVOID)pNtMapViewOfSection, jmp, sizeof(jmp), &R);
    }

    FreeLibrary(hDll2);
    return oep;
}


}



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

int Monitor::LoadFile(const std::wstring& filePath)
{
    WCHAR cmd[MAX_PATH] = { 0 };
    wcscpy_s(cmd, filePath.c_str());
    STARTUPINFO si = { 0 };
    si.cb = sizeof(si);
    memset(&mProcessInfo, 0, sizeof(mProcessInfo));
    BOOL success = CreateProcess(filePath.c_str(), cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &mProcessInfo);

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

    char bytesOfNtMapViewOfSectionPad[32] = { 0 };
    ReadProcessMemory(mProcessInfo.hProcess, (LPVOID)GetProcAddress((HMODULE)param.ntdllBase, "NtMapViewOfSection"), bytesOfNtMapViewOfSectionPad, sizeof(bytesOfNtMapViewOfSectionPad), &R);
    assert(bytesOfNtMapViewOfSectionPad[0] == '\xb8');  // mov eax,28h
    param.NtMapViewOfSectionServerId = *(PDWORD)&bytesOfNtMapViewOfSectionPad[1];
    assert(bytesOfNtMapViewOfSectionPad[5] == '\xba');  // mov edx,offset XXX
    param.f_Wow64SystemServiceCall = (LPVOID)*(PDWORD)&bytesOfNtMapViewOfSectionPad[6];
    assert(*(PWORD)&bytesOfNtMapViewOfSectionPad[10] == 0xd2ff);  // call edx
    assert(param.f_Wow64SystemServiceCall != 0);
    PVOID oep = Detail::BuildRemoteData(mProcessInfo.hProcess, TEXT("C:\\Projects\\ApiMonitor\\bin\\Win32\\Release\\PayLoad.dll"));

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
    return mBp.break_always || mBp.break_call_from || mBp.break_invoke_time || mBp.break_next_time;
}

void ApiInfoItem::BreakAlways()
{
    RemoveBp();
    mBp.break_always = true;
}

void ApiInfoItem::BreakNextTime()
{
    RemoveBp();
    mBp.break_next_time = true;
}

void ApiInfoItem::BreakOnTime(int time)
{
    RemoveBp();
    mBp.break_invoke_time = true;
    mBp.invoke_time = time;
}

void ApiInfoItem::RemoveBp()
{
    mBp.break_call_from = false;
    mBp.break_invoke_time = false;
    mBp.break_next_time = false;
    mBp.break_always = false;
}

std::string ApiInfoItem::GetBpDescription() const
{
    assert(mBp.break_next_time + mBp.break_call_from + mBp.break_invoke_time <= 1);
    if (mBp.break_always)
        return "Always";
    else if (mBp.break_next_time)
        return "Next Time";
    else if (mBp.break_invoke_time)
    {
        std::stringstream ss;
        ss << mBp.invoke_time;
        return std::string("times == ") + ss.str();
    }
    else
        return "";
}
