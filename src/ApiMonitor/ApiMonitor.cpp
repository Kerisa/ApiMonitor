
#include <cassert>
#include <iostream>
#include <vector>
#include <windows.h>
#include "def.h"

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
    return (PVOID)(entry - (ULONG_PTR)hDll2 + (ULONG_PTR)newBase);
    //return (PVOID)((ULONG_PTR)((PIMAGE_NT_HEADERS)(imageData + ((PIMAGE_DOS_HEADER)imageData)->e_lfanew))->OptionalHeader.AddressOfEntryPoint + (ULONG_PTR)newBase);
    //return (PVOID)((ULONG_PTR)executeProc - (ULONG_PTR)imageData + (ULONG_PTR)newBase);
}

int main(int argc, char** argv)
{
    WCHAR app[MAX_PATH] = { 0 };
    WCHAR cmd[MAX_PATH] = { 0 };
    MultiByteToWideChar(CP_ACP, 0, argv[1], -1, app, MAX_PATH - 1);
    wcscpy_s(cmd, app);
    STARTUPINFO si = { 0 };
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };
    BOOL success = CreateProcess(app, cmd, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);

    LPVOID paramBase = VirtualAllocEx(pi.hProcess, (LPVOID)PARAM::PARAM_ADDR, PARAM::PARAM_SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    PVOID oep = BuildRemoteData(pi.hProcess, TEXT("C:\\Projects\\ApiMonitor\\bin\\Win32\\Release\\PayLoad.dll"));

    SIZE_T R = 0;
    //FN_LdrInitializeThunk pLdrInitializeThunk = (FN_LdrInitializeThunk)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrInitializeThunk");
    //char scode[8] = { 0 };
    //scode[0] = '\x68';
    //*(PDWORD)&scode[1] = (DWORD)oep;
    //scode[5] = '\xc3';
    //scode[6] = '\xeb';
    //scode[7] = '\xf8';
    //WriteProcessMemory(pi.hProcess, (LPVOID)((ULONG_PTR)pLdrInitializeThunk - 6), scode, 8, &R);

    PARAM param;
    //memcpy_s(param.LdrInitializeThunkOEP, sizeof(param.LdrInitializeThunkOEP), pLdrInitializeThunk, 2);
    param.ntdllBase = (LPVOID)GetModuleHandleA("ntdll.dll");
    param.dwProcessId = pi.dwProcessId;
    param.dwThreadId = pi.dwThreadId;
    param.ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(pi.hThread, &param.ctx);
    WriteProcessMemory(pi.hProcess, paramBase, &param, sizeof(param), &R);
    CONTEXT copy = param.ctx;
    copy.Eax = (DWORD)oep;
    SetThreadContext(pi.hThread, &copy);

    //WriteProcessMemory(pi.hProcess, (LPVOID)((ULONG_PTR)pLdrInitializeThunk - 6), scode, 8, &R);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}