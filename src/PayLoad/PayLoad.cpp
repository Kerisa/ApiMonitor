
#include <string>
#include <Windows.h>
#include "def.h"


ULONG_PTR MiniGetFunctionAddress(ULONG_PTR phModule, const char* pProcName)
{
    PIMAGE_DOS_HEADER pimDH;
    PIMAGE_NT_HEADERS pimNH;
    PIMAGE_EXPORT_DIRECTORY pimED;
    ULONG_PTR pResult = 0;
    PDWORD pAddressOfNames;
    PWORD  pAddressOfNameOrdinals;
    DWORD i;
    if (!phModule)
        return 0;
    pimDH = (PIMAGE_DOS_HEADER)phModule;
    pimNH = (PIMAGE_NT_HEADERS)((char*)phModule + pimDH->e_lfanew);
    pimED = (PIMAGE_EXPORT_DIRECTORY)(phModule + pimNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    if (pimNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0 || (ULONG_PTR)pimED <= phModule)
        return 0;
    if ((ULONG_PTR)pProcName < 0x10000)
    {
        if ((ULONG_PTR)pProcName >= pimED->NumberOfFunctions + pimED->Base || (ULONG_PTR)pProcName < pimED->Base)
            return 0;
        pResult = phModule + ((PDWORD)(phModule + pimED->AddressOfFunctions))[(ULONG_PTR)pProcName - pimED->Base];
    }
    else
    {
        pAddressOfNames = (PDWORD)(phModule + pimED->AddressOfNames);
        for (i = 0; i < pimED->NumberOfNames; ++i)
        {
            char* pExportName = (char*)(phModule + pAddressOfNames[i]);
            if (!strcmp(pProcName, pExportName))
            {
                pAddressOfNameOrdinals = (PWORD)(phModule + pimED->AddressOfNameOrdinals);
                pResult = phModule + ((PDWORD)(phModule + pimED->AddressOfFunctions))[pAddressOfNameOrdinals[i]];
                break;
            }
        }
    }
    return pResult;
}

class MLog
{
public:
    MLog() { mBuf[0] = '\0'; }
    MLog& operator<<(const char* s)
    {
        if (s)
            strcat_s(mBuf, sizeof(mBuf), s);
        else
            strcat_s(mBuf, sizeof(mBuf), "(null passed)");
        return *this;
    }
    MLog& operator<<(int i)
    {
        char buf[32];
        sprintf_s(buf, sizeof(buf), "%d", i);
        strcat_s(mBuf, sizeof(mBuf), buf);
        return *this;
    }
    MLog& operator<<(unsigned long i)
    {
        char buf[32];
        sprintf_s(buf, sizeof(buf), "%u", i);
        strcat_s(mBuf, sizeof(mBuf), buf);
        return *this;
    }
    MLog& operator<<(unsigned __int64 i)
    {
        char buf[32];
        sprintf_s(buf, sizeof(buf), "%llu", i);
        strcat_s(mBuf, sizeof(mBuf), buf);
        return *this;
    }
    MLog& operator<<(void* p)
    {
        char buf[32];
        sprintf_s(buf, sizeof(buf), "0x%p", p);
        strcat_s(mBuf, sizeof(mBuf), buf);
        return *this;
    }

    MLog& operator<<(unsigned int i) { return operator<<(static_cast<unsigned long>(i)); }
    MLog& operator<<(HMODULE i) { return operator<<(static_cast<void*>(i)); }
    const char* str() const { return mBuf; }
private:
    static char mBuf[1024];
};
char MLog::mBuf[1024];


#define Vlog(cond) do { \
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR; \
    MLog ml; \
    ml << " [" << param->dwProcessId << "." << param->dwThreadId << "] " << cond << "\n"; \
    param->f_OutputDebugStringA(ml.str()); \
  } while (0)

void CollectModuleInfo(HMODULE hmod, const char* modname, const char* modpath)
{
    Vlog("[CollectModuleInfo] enter.");
    const char* lpImage = (const char*)hmod;
    PIMAGE_DOS_HEADER imDH = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS imNH = (PIMAGE_NT_HEADERS)((char*)lpImage + imDH->e_lfanew);
    DWORD exportRVA = imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY imED = (PIMAGE_EXPORT_DIRECTORY)(lpImage + exportRVA);
    long pExportSize = imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!(pExportSize == 0 || (ULONG_PTR)imED <= (ULONG_PTR)lpImage))
    {
        // 存在导出表
        if (imED->NumberOfFunctions > 0)
        {
            PWORD lpOrdinals = imED->AddressOfNameOrdinals ? (PWORD)(lpImage + imED->AddressOfNameOrdinals) : 0;
            PDWORD lpNames = imED->AddressOfNames ? (PDWORD)(lpImage + imED->AddressOfNames) : 0;
            PDWORD lpRvas = (PDWORD)(lpImage + imED->AddressOfFunctions);
            PIMAGE_SECTION_HEADER ish = (PIMAGE_SECTION_HEADER)(imNH + 1);
            int nsec = imNH->FileHeader.NumberOfSections;
            for (DWORD i = 0; i < imED->NumberOfFunctions; ++i)
            {
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
                Vlog("orgRVA: " << rvafunc << ", apiBase: " << rvafunc << ", apiName: " << (oftName ? lpImage + oftName : "<null>"));

                // 判断是否为转向函数导出
                if (!(rvafunc >= exportRVA && rvafunc < (exportRVA + pExportSize)))
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
                }
                else
                {
                    // 是转向函数，设定转向信息
                    Vlog("redirectApi: " << lpImage + rvafunc);
                }
            }
        }
    }
    Vlog("[CollectModuleInfo] exit.");
}

class HookEntries
{
public:
    static HookEntries msEntries;
    struct Entry
    {
        typedef void (__stdcall * FN_HookFunction)(uint32_t self_index);
        uint32_t        mSelfIndex;
        char            mBytesCode[32];
        char*           mFuncName;
        char            mParams[128];
        FN_HookFunction mHookFunction;

        void SetFuncName(const char* name)
        {
            if (!name)
                return;
            PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
            if (mFuncName)
                param->f_HeapFree(param->f_GetProcessHeap(), 0, mFuncName);
            size_t len = strlen(name);
            mFuncName = (char*)param->f_HeapAlloc(param->f_GetProcessHeap(), 0, len + 1);
            strcpy_s(mFuncName, len + 1, name);
        }

        void Reset(uint32_t index)
        {
            mHookFunction = CommonHookFunction;
            mSelfIndex = index;
            mFuncName = 0;
            memset(mBytesCode, 0, sizeof(mBytesCode));
            memset(mParams,    0, sizeof(mParams));
        }
    };
    static void __stdcall CommonHookFunction(uint32_t self_index)
    {
        Entry* e = msEntries.GetEntry(self_index);
        Vlog("[HookEntries::CommonHookFunction] self index: " << self_index
            << ", func name: " << (e ? e->mFuncName : "<idx error>")
            << ", invoke time: " << (e ? *(int*)e->mParams : -1));
        if (e)
            ++(*(int*)e->mParams);
    }
    static NTSTATUS __stdcall LdrLoadDllHookFunction(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle)
    {
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        NTSTATUS s = param->f_LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);
        wchar_t wbuf[128] = { 0 };
        wcsncpy_s(wbuf, _countof(wbuf), ModuleFileName->Buffer, min(ModuleFileName->Length, _countof(wbuf) - 1));
        wbuf[min(ModuleFileName->Length, _countof(wbuf) - 1)] = L'\0';
        Vlog("[HookEntries::LdrLoadDllHookFunction] Name: " << wbuf << ", Handle: " << ModuleHandle);
        return s;
    }

    void Init(FN_VirtualAlloc alloctor, size_t count)
    {
        if (!mEntryArray)
        {
            mEntryCounts = count;
            mEntryUsed = 0;
            mEntryArray = (Entry*)alloctor(0, sizeof(Entry) * count, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            Vlog("[HookEntries::AddEntry] init, total: " << mEntryCounts << ", addr: " << (ULONG_PTR)mEntryArray);
        }
    }

    Entry* AddEntry()
    {
        if (mEntryUsed >= mEntryCounts)
        {
            Vlog("[HookEntries::AddEntry] full, total: " << mEntryCounts);
            return nullptr;
        }
        Entry* ret = &mEntryArray[mEntryUsed];
        ret->Reset(mEntryUsed);
        ++mEntryUsed;
        Vlog("[HookEntries::AddEntry] entry: " << ret << ", used count: " << mEntryUsed);
        return ret;
    }

    Entry* GetEntry(uint32_t i)
    {
        return i < mEntryUsed ? &mEntryArray[i] : nullptr;
    }

private:
    uint32_t mEntryCounts{ 0 };
    uint32_t mEntryUsed{ 0 };
    Entry*   mEntryArray{ nullptr };
};
HookEntries HookEntries::msEntries;


ULONG_PTR AddHookRoutine(HMODULE hmod, PVOID oldEntry, PVOID oldRvaPtr, const char* funcName)
{
    Vlog("[AddHookRoutine] module: " << hmod << ", name: " << funcName << ", entry: " << oldEntry << ", rva: " << (LPVOID)*(PDWORD)oldRvaPtr);
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
    HookEntries::msEntries.Init(param->f_VirtualAlloc, 32768);
    HookEntries::Entry* e = HookEntries::msEntries.AddEntry();
    if (!e)
    {
        Vlog("[AddHookRoutine] add new entry failed, skip");
        return 0;
    }
    e->SetFuncName(funcName);

    if (strcmp(funcName, "LdrLoadDll"))
    {
        //
        // push edx
        // push ecx
        // push entry_index
        // push continue_offset
        // push hook_func
        // ret
        // pop ecx              ; <--- here continue_offset
        // pop edx
        // push original_func
        // ret
        //

        e->mBytesCode[0] = '\x52';
        e->mBytesCode[1] = '\x51';
        e->mBytesCode[2] = '\x68';
        *(ULONG_PTR*)&e->mBytesCode[3] = (ULONG_PTR)e->mSelfIndex;
        e->mBytesCode[7] = '\x68';
        *(ULONG_PTR*)&e->mBytesCode[8] = (ULONG_PTR)&e->mBytesCode[18];
        e->mBytesCode[12] = '\x68';
        *(ULONG_PTR*)&e->mBytesCode[13] = (ULONG_PTR)e->mHookFunction;
        e->mBytesCode[17] = '\xc3';
        e->mBytesCode[18] = '\x59';
        e->mBytesCode[19] = '\x5a';
        e->mBytesCode[20] = '\x68';
        *(ULONG_PTR*)&e->mBytesCode[21] = (ULONG_PTR)oldEntry;
        e->mBytesCode[25] = '\xc3';
        e->mBytesCode[26] = '\xcc';
    }
    else
    {
        // for LdrLoadDll

        //
        // push <LdrLoadDllHookFunction>
        // ret
        //
        Vlog("[AddHookRoutine] handle for LdrLoadDll");
        e->mBytesCode[0] = '\x68';
        *(ULONG_PTR*)&e->mBytesCode[1] = (ULONG_PTR)HookEntries::LdrLoadDllHookFunction;
        e->mBytesCode[5] = '\xcc';
    }

    ULONG_PTR newRva = (ULONG_PTR)e->mBytesCode - (ULONG_PTR)hmod;
    Vlog("[AddHookRoutine] finish, new rva: " << (PVOID)newRva);
    return newRva;
}

void HookModuleExportTable(HMODULE hmod)
{
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;

    Vlog("[HookModuleExportTable] enter, hmod: " << (LPVOID)hmod);
    const char* lpImage = (const char*)hmod;
    PIMAGE_DOS_HEADER imDH = (PIMAGE_DOS_HEADER)lpImage;
    PIMAGE_NT_HEADERS imNH = (PIMAGE_NT_HEADERS)((char*)lpImage + imDH->e_lfanew);
    DWORD exportRVA = imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    PIMAGE_EXPORT_DIRECTORY imED = (PIMAGE_EXPORT_DIRECTORY)(lpImage + exportRVA);
    long pExportSize = imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (pExportSize == 0 || (ULONG_PTR)imED <= (ULONG_PTR)lpImage)
    {
        Vlog("[HookModuleExportTable] export table not exist.");
        return;
    }

    // 创建虚拟导出表
    Vlog("[HookModuleExportTable] create new export table");
    PIMAGE_EXPORT_DIRECTORY imEDNew = (PIMAGE_EXPORT_DIRECTORY)param->f_VirtualAlloc(0, pExportSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    memcpy_s(imEDNew, pExportSize, imED, pExportSize);
    DWORD delta = (char*)imEDNew - (char*)imED;
    imEDNew->AddressOfFunctions    += delta;
    imEDNew->AddressOfNames        += delta;
    imEDNew->AddressOfNameOrdinals += delta;
    PDWORD oldFunc = (PDWORD)(lpImage + imED->AddressOfFunctions);
    PDWORD newFunc = (PDWORD)(lpImage + imEDNew->AddressOfFunctions);
    for (int i = 0; i < imED->NumberOfFunctions; ++i)
    {
        newFunc[i] += delta;
    }

    DWORD oldProtect = 0;
    param->f_VirtualProtect(oldFunc, imEDNew->NumberOfFunctions * sizeof(DWORD), PAGE_READWRITE, &oldProtect);

    Vlog("[HookModuleExportTable] replace exdisting export table, count: " << imED->NumberOfFunctions);
    char tmpFuncNameBuffer[32] = { 0 };
    PDWORD lpNames    = imED->AddressOfNames ? (PDWORD)(lpImage + imED->AddressOfNames) : 0;
    PWORD  lpOrdinals = imED->AddressOfNameOrdinals ? (PWORD)(lpImage + imED->AddressOfNameOrdinals) : 0;
    for (int i = 0; i < imED->NumberOfFunctions; ++i)
    {
        if (oldFunc[i] >= exportRVA && oldFunc[i] < exportRVA + pExportSize)
        {
            Vlog("[HookModuleExportTable] skip forword function: " << (lpImage + oldFunc[i]));
            continue;
        }

        // 查找名称
        const char* funcName = "";
        for (int k = 0; k < imED->NumberOfNames; ++k)
        {
            if (lpOrdinals[k] == i)
            {
                funcName = lpImage + lpNames[k];
                break;
            }
        }
        if (funcName[0] == '\0')
        {
            sprintf_s(tmpFuncNameBuffer, sizeof(tmpFuncNameBuffer), "Number Export:%d", i + imED->Base);
            funcName = tmpFuncNameBuffer;
        }
        ULONG_PTR newRva = AddHookRoutine(hmod, (PVOID)(lpImage + oldFunc[i]), &oldFunc[i], funcName);
        if (newRva)
            newFunc[i] = newRva;
        else
            newFunc[i] = oldFunc[i];
    }

    DWORD oldProtect2 = 0;
    param->f_VirtualProtect(&imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, sizeof(DWORD), PAGE_READWRITE, &oldProtect2);
    imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = (DWORD)imEDNew - (DWORD)lpImage;
    if (oldProtect2 != 0)
        param->f_VirtualProtect(&imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, sizeof(DWORD), oldProtect2, &oldProtect2);

    Vlog("[HookModuleExportTable] finish");
    if (oldProtect != 0)
        param->f_VirtualProtect(oldFunc, imEDNew->NumberOfFunctions * sizeof(DWORD), oldProtect, &oldProtect);
}

void HookLoadedModules()
{
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;

    tagMODULEENTRY32 me32;
    HANDLE hModuleSnap = param->f_CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, param->dwProcessId);
    if (hModuleSnap == INVALID_HANDLE_VALUE)
    {
        Vlog("[HookLoadedModules] CreateToolhelp32Snapshot failed.");
        return;
    }

    me32.dwSize = sizeof(tagMODULEENTRY32);
    if (!param->f_Module32First(hModuleSnap, &me32))
    {
        Vlog("[HookLoadedModules] Module32First failed.");
        return;
    }

    do
    {
        Vlog("[HookLoadedModules] process: " << me32.szModule << ", image base: " << (LPVOID)me32.modBaseAddr << ", path: " << me32.szExePath);
        CollectModuleInfo((HMODULE)me32.modBaseAddr, me32.szModule, me32.szExePath);
        HookModuleExportTable((HMODULE)me32.modBaseAddr);

    } while (param->f_Module32Next(hModuleSnap, &me32));

    param->f_CloseHandle(hModuleSnap);
}

void Entry2()
{
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
    param->f_LdrLoadDll = (FN_LdrLoadDll)MiniGetFunctionAddress((ULONG_PTR)param->ntdllBase, "LdrLoadDll");
    param->f_LdrInitializeThunk = (FN_LdrInitializeThunk)MiniGetFunctionAddress((ULONG_PTR)param->ntdllBase, "LdrInitializeThunk");
    wchar_t buffer[MAX_PATH] = L"kernelbase.dll";
    UNICODE_STRING name = { 0 };
    name.Length = wcslen(buffer) * sizeof(wchar_t);
    name.Buffer = buffer;
    name.MaximumLength = sizeof(buffer);
    HANDLE hKernel = 0;
    NTSTATUS status = param->f_LdrLoadDll(0, 0, &name, &hKernel);
    param->kernelBase = (LPVOID)hKernel;
    param->f_GetProcAddress = (FN_GetProcAddress)MiniGetFunctionAddress((ULONG_PTR)hKernel, "GetProcAddress");

    // get more api
    param->f_GetModuleHandleA = (FN_GetModuleHandleA)param->f_GetProcAddress((HMODULE)param->kernelBase, "GetModuleHandleA");
    param->f_OpenThread = (FN_OpenThread)param->f_GetProcAddress((HMODULE)param->kernelBase, "OpenThread");
    param->f_SuspendThread = (FN_SuspendThread)param->f_GetProcAddress((HMODULE)param->kernelBase, "SuspendThread");
    param->f_SetThreadContext = (FN_SetThreadContext)param->f_GetProcAddress((HMODULE)param->kernelBase, "SetThreadContext");
    param->f_ResumeThread = (FN_ResumeThread)param->f_GetProcAddress((HMODULE)param->kernelBase, "ResumeThread");
    param->f_CloseHandle = (FN_CloseHandle)param->f_GetProcAddress((HMODULE)param->kernelBase, "CloseHandle");
    param->f_CreateThread = (FN_CreateThread)param->f_GetProcAddress((HMODULE)param->kernelBase, "CreateThread");
    param->f_OutputDebugStringA = (FN_OutputDebugStringA)param->f_GetProcAddress((HMODULE)param->kernelBase, "OutputDebugStringA");
    param->f_VirtualAlloc = (FN_VirtualAlloc)param->f_GetProcAddress((HMODULE)param->kernelBase, "VirtualAlloc");
    param->f_VirtualProtect = (FN_VirtualProtect)param->f_GetProcAddress((HMODULE)param->kernelBase, "VirtualProtect");

    param->kernel32 = (LPVOID)param->f_GetModuleHandleA("kernel32.dll");
    param->f_CreateToolhelp32Snapshot = (FN_CreateToolhelp32Snapshot)param->f_GetProcAddress((HMODULE)param->kernel32, "CreateToolhelp32Snapshot");
    param->f_Module32First = (FN_Module32First)param->f_GetProcAddress((HMODULE)param->kernel32, "Module32First");
    param->f_Module32Next = (FN_Module32Next)param->f_GetProcAddress((HMODULE)param->kernel32, "Module32Next");
    param->f_HeapAlloc = (FN_HeapAlloc)param->f_GetProcAddress((HMODULE)param->kernel32, "HeapAlloc");    
    param->f_HeapFree = (FN_HeapFree)param->f_GetProcAddress((HMODULE)param->kernel32, "HeapFree");
    param->f_GetProcessHeap = (FN_GetProcessHeap)param->f_GetProcAddress((HMODULE)param->kernel32, "GetProcessHeap");

    {
        // debug message
        wcscpy_s(buffer, L"User32.dll");
        name.Length = wcslen(buffer) * sizeof(wchar_t);
        HANDLE hUser32 = 0;
        status = param->f_LdrLoadDll(0, 0, &name, &hUser32);
        FN_MessageBoxA pMessageBox = (FN_MessageBoxA)param->f_GetProcAddress((HMODULE)hUser32, "MessageBoxA");
        char buf[32];
        sprintf_s(buf, sizeof(buf), "pid: %#x", param->dwProcessId);
        pMessageBox(0, "I'm here", buf, MB_ICONINFORMATION);
    }

    HookLoadedModules();
}

DWORD WINAPI Recover(LPVOID pv)
{
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;

    Vlog("[Recover]");

    HANDLE hT = param->f_OpenThread(THREAD_ALL_ACCESS, FALSE, param->dwThreadId);
    param->f_SuspendThread(hT);
    //param->ctx.Eip = (ULONG_PTR)param->f_LdrInitializeThunk + 2;
    param->f_SetThreadContext(hT, &param->ctx);
    param->f_ResumeThread(hT);
    param->f_CloseHandle(hT);
    return 0;
}

/*__declspec(naked)*/ void Entry()
{
    Entry2();

    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
    param->f_CreateThread(0, 0, Recover, 0, 0, 0);
    while (1) { }
}

#pragma optimize("", off)
void Alias(const void* var) {
    if (0) {
        Entry();
    }
}
#pragma optimize("", on)

BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_DETACH)
    {
        Alias(0);
    }

    return TRUE;
}

