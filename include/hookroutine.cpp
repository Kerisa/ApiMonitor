
#include <algorithm>
#include <map>
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