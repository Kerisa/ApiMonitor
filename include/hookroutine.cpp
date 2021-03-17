
#include <algorithm>
#include <cassert>
#include <map>
#include <vector>
#include "hookroutine.h"

using Allocator::string;

bool IsMemoryReadable(LPVOID addr)
{
    __try
    {
        char c = *(char*)addr;
        return true;
    }
    __except (1)
    {
        return false;
    }
}

string GetDllNameFromExportDirectory(HMODULE hmod)
{
    const char* lpImage = (const char*)hmod;
    PIMAGE_DOS_HEADER imDH = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS imNH = (PIMAGE_NT_HEADERS)((char*)lpImage + imDH->e_lfanew);
    DWORD exportRVA = imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY imED = (PIMAGE_EXPORT_DIRECTORY)(lpImage + exportRVA);
    long pExportSize = imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (pExportSize == 0 || !IsMemoryReadable(imED) || imED->Characteristics != 0 || imED->MajorVersion != 0 || imED->MinorVersion != 0)
        return "";
    else
        return lpImage + imED->Name;
}

void CheckDataExportOrForwardApi(bool& dataExp, bool& forwardApi, DWORD rvafunc, PIMAGE_DATA_DIRECTORY exportDir, PIMAGE_NT_HEADERS imNH, const char* lpImage)
{
    dataExp = false;
    forwardApi = false;
    int nsec = imNH->FileHeader.NumberOfSections;
    PIMAGE_SECTION_HEADER ish = (PIMAGE_SECTION_HEADER)(imNH + 1);
    // 判断是否为转向函数导出
    if (!(rvafunc >= exportDir->VirtualAddress && rvafunc < (exportDir->VirtualAddress + exportDir->Size)))
    {
        // 如果不是转向函数则遍历整个区段判断是否为数据导出。
        // 由于是通过区段属性判断因此并非完全准确，但大部分情况下是准确的
        BOOL isDataExport = TRUE;
        PIMAGE_SECTION_HEADER ishcur;
        for (int j = 0; j < nsec; ++j)
        {
            ishcur = ish + j;
            if (rvafunc >= ishcur->VirtualAddress && rvafunc < (ishcur->VirtualAddress + ishcur->Misc.VirtualSize))
            {
                if (ishcur->Characteristics & IMAGE_SCN_MEM_EXECUTE)
                {
                    isDataExport = FALSE;
                    break;
                }
            }
        }
        if (isDataExport)
            Vlog("dataApi: -");
        dataExp = !!isDataExport;
    }
    else
    {
        // 是转向函数，设定转向信息
        Vlog("redirectApi: " << lpImage + rvafunc);
        forwardApi = true;
    }
}

void CollectModuleInfo(HMODULE hmod, const string& modname, const string& modpath, PipeDefine::msg::ModuleApis& msgModuleApis)
{
    Vlog("[CollectModuleInfo] enter.");

    msgModuleApis.module_name.assign(modname);
    msgModuleApis.module_path.assign(modpath);
    msgModuleApis.module_base = (long long)hmod;

    const char* lpImage = (const char*)hmod;
    PIMAGE_DOS_HEADER imDH = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS imNH = (PIMAGE_NT_HEADERS)((char*)lpImage + imDH->e_lfanew);
    DWORD exportRVA = imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY imED = (PIMAGE_EXPORT_DIRECTORY)(lpImage + exportRVA);
    long pExportSize = imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (pExportSize == 0 || !IsMemoryReadable(imED))
    {
        Vlog("[CollectModuleInfo] export table empty or bad address, size: " << pExportSize << ", va: " << imED);
        return;
    }

    // 存在导出表
    if (imED->NumberOfFunctions <= 0)
    {
        Vlog("[CollectModuleInfo] number of functions <= 0.");
        return;
    }
    PWORD lpOrdinals = imED->AddressOfNameOrdinals ? (PWORD)(lpImage + imED->AddressOfNameOrdinals) : 0;
    PDWORD lpNames = imED->AddressOfNames ? (PDWORD)(lpImage + imED->AddressOfNames) : 0;
    PDWORD lpRvas = (PDWORD)(lpImage + imED->AddressOfFunctions);
    PIMAGE_SECTION_HEADER ish = (PIMAGE_SECTION_HEADER)(imNH + 1);
    int nsec = imNH->FileHeader.NumberOfSections;
    for (DWORD i = 0; i < imED->NumberOfFunctions; ++i)
    {
        PipeDefine::msg::ModuleApis::ApiDetail ad;
        DWORD rvafunc = lpRvas[i];
        DWORD oftName = 0;
        // 找出函数对应的名称
        if (lpNames && lpOrdinals)
        {
            for (DWORD k = 0; k < imED->NumberOfNames; ++k)
            {
                if (lpOrdinals[k] == i)
                {
                    oftName = lpNames[k];
                    break;
                }
            }
        }
        if (oftName)
            Vlog("orgRVA: " << rvafunc << ", apiBase: " << rvafunc << ", apiName: " << (lpImage + oftName));
        else
            Vlog("orgRVA: " << rvafunc << ", apiBase: " << rvafunc << ", apiName: ordinal " << i);

        bool dataExp = false;
        bool forwardApi = false;
        CheckDataExportOrForwardApi(dataExp, forwardApi, rvafunc, &imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT], imNH, lpImage);

        ad.rva = rvafunc;
        ad.va = rvafunc + (DWORD)lpImage;
        if (oftName)
            ad.name = lpImage + oftName;
        else
        {
            SStream ml;
            ml << i;
            ad.name = string("ordinal ") + ml.str();
        }
        if (forwardApi)
            ad.forwardto = lpImage + rvafunc;
        ad.data_export = dataExp;
        ad.forward_api = forwardApi;
        msgModuleApis.apis.push_back(ad);
    }
    Vlog("[CollectModuleInfo] exit.");
}


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
    std::vector<unsigned char> remoteMemory(0x200);
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
        jmp[1] = static_cast<char>(position - (0x100 + 0x2));
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