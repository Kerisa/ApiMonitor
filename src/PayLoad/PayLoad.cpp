
#include <array>
#include <vector>
#include <Windows.h>
#include "def.h"
//#include "pipe.pb.h"
#include "allocator.h"
#include "pipemessage.h"


using Allocator::string;
using Allocator::stringstream;

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
    MLog& operator<<(const Allocator::string& s)
    {
        strcat_s(mBuf, sizeof(mBuf), s.c_str());
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
    char mBuf[1024];
};

#define PRINT_DEBUG_LOG

#ifdef PRINT_DEBUG_LOG
    #define Vlog(cond) do { \
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR; \
        MLog ml; \
        ml << " [" << param->dwProcessId << "." << param->dwThreadId << "] " << cond << "\n"; \
        param->f_OutputDebugStringA(ml.str()); \
      } while (0)
#else
    #define Vlog(cond)
#endif

class PipeLine
{
public:
    static PipeLine msPipe;

    bool ConnectServer()
    {
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        int busyRetry = 5;
        Vlog("[PipeLine::ConnectServer]");
        while (busyRetry--)
        {
            mPipe = param->f_CreateFileA(PipeDefine::PIPE_NAME, GENERIC_READ | GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL
            );
            if (mPipe != INVALID_HANDLE_VALUE)
                break;

            if (param->f_GetLastError() != ERROR_PIPE_BUSY)
            {
                Vlog("[PipeLine::ConnectServer] Could not open pipe. GLE: " << param->f_GetLastError());
                return false;
            }

            if (!param->f_WaitNamedPipeA(PipeDefine::PIPE_NAME, NMPWAIT_USE_DEFAULT_WAIT))
            {
                Vlog("[PipeLine::ConnectServer] Could not open pipe: 20 second wait timed out.");
                return false;
            }
        }

        DWORD dwMode = PIPE_READMODE_MESSAGE;
        if (!param->f_SetNamedPipeHandleState(mPipe, &dwMode, NULL, NULL))
        {
            Vlog("[PipeLine::ConnectServer] SetNamedPipeHandleState failed. GLE: " << param->f_GetLastError());
            return false;
        }

        Vlog("[PipeLine::ConnectServer] connected. " << mPipe);
        return mPipe != INVALID_HANDLE_VALUE;
    }

    bool Send(PipeDefine::MsgReq type, const std::vector<char, Allocator::allocator<char>> & content)
    {
        if (mPipe == INVALID_HANDLE_VALUE)
        {
            Vlog("[PipeLine::Send] pipe not ready.");
            return false;
        }

        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        DWORD dummy = 0;
        std::vector<char, Allocator::allocator<char>> m(PipeDefine::Message::HeaderLength);
        PipeDefine::Message* ptr = (PipeDefine::Message*)m.data();
        ptr->Req = type;
        ptr->ContentSize = content.size();
        m.insert(m.end(), content.begin(), content.end());
        Vlog("[PipeLine::Send] msg type: " << type << ", size: " << m.size());
        BOOL ret = param->f_WriteFile(mPipe, m.data(), m.size(), &dummy, NULL);
        if (!ret)
            Vlog("[PipeLine::Send] result: " << ret << ", err: " << param->f_GetLastError());
        return !!ret;
    }

    bool Recv(PipeDefine::MsgAck & msg, std::vector<char, Allocator::allocator<char>> & content)
    {
        if (mPipe == INVALID_HANDLE_VALUE)
        {
            Vlog("[PipeLine::Recv] pipe not ready.");
            return false;
        }
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        BOOL ret = 0;
        DWORD dummy = 0;
        DWORD dataToRead = PipeDefine::Message::HeaderLength;
        std::vector<char, Allocator::allocator<char>> m(1024*1024);
        ret = param->f_ReadFile(mPipe, m.data(), m.size(), &dummy, NULL);
        if (!ret)
        {
            Vlog("[PipeLine::Recv] pipe read header failed, err: " << param->f_GetLastError());
            return false;
        }
        PipeDefine::Message* ptr = (PipeDefine::Message*)m.data();
        if (ptr->ContentSize >= m.size() - PipeDefine::Message::HeaderLength)
        {
            Vlog("[PipeLine::Recv] message may corrupted, type: " << ptr->Ack << ", size: " << ptr->ContentSize);
            return false;
        }
        msg = ptr->Ack;
        content.assign(ptr->Content, ptr->Content + ptr->ContentSize);
        Vlog("[PipeLine::Recv] msg type: " << msg << ", size: " << content.size());
        return true;
    }

    HANDLE mPipe;
};
PipeLine PipeLine::msPipe;

class HookEntries
{
public:
    static HookEntries msEntries;
    struct Entry
    {
        static constexpr size_t ByteCodeLength = 32;
        typedef void (__stdcall * FN_HookFunction)(uint32_t self_index);
        uint32_t                mSelfIndex;
        char*                   mBytesCode;
        string                  mFuncName;
        std::array<char, 128>   mParams;
        FN_HookFunction         mHookFunction;

        Entry() { mBytesCode = (char*)Allocator::MallocExe(ByteCodeLength); }

        void Reset(uint32_t index)
        {
            mHookFunction = CommonHookFunction;
            mSelfIndex = index;
            memset(mBytesCode, 0, ByteCodeLength);
            memset(mParams.data(), 0, mParams.size());
            mFuncName.clear();
        }
    };
    static void __stdcall CommonHookFunction(uint32_t self_index)
    {
        Entry* e = msEntries.GetEntry(self_index);
        Vlog("[HookEntries::CommonHookFunction] self index: " << self_index
            << ", func name: " << (e ? e->mFuncName.c_str() : "<idx error>")
            << ", invoke time: " << (e ? *(int*)e->mParams.data() : -1));
        
        if (e)
            _InlineInterlockedAdd((LONG*)e->mParams.data(), 1);
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

    Entry* AddEntry()
    {
        Entry* ret = (Entry*)Allocator::Malloc(sizeof(Entry));
        ret->Entry::Entry();
        ret->Reset(mEntryArray.size());
        mEntryArray.push_back(ret);
        Vlog("[HookEntries::AddEntry] entry: " << ret << ", added count: " << mEntryArray.size());
        return ret;
    }

    Entry* GetEntry(uint32_t i)
    {
        return i < mEntryArray.size() ? mEntryArray[i] : nullptr;
    }

private:
    std::vector<Entry*, Allocator::allocator<Entry*>> mEntryArray;
};
HookEntries HookEntries::msEntries;


ULONG_PTR AddHookRoutine(HMODULE hmod, PVOID oldEntry, PVOID oldRvaPtr, const char* funcName)
{
    Vlog("[AddHookRoutine] module: " << hmod << ", name: " << funcName << ", entry: " << oldEntry << ", rva: " << (LPVOID)*(PDWORD)oldRvaPtr);
    HookEntries::Entry* e = HookEntries::msEntries.AddEntry();
    if (!e)
    {
        Vlog("[AddHookRoutine] add new entry failed, skip");
        return 0;
    }
    e->mFuncName = funcName;

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

void CollectModuleInfo(HMODULE hmod, const char* modname, const char* modpath, PipeDefine::Msg_ModuleApis& pbModuleApis)
{
    Vlog("[CollectModuleInfo] enter.");

    pbModuleApis.module_name = modname;
    pbModuleApis.module_path = modpath;
    pbModuleApis.module_base = (long long)hmod;

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
                PipeDefine::Msg_ModuleApis::ApiDetail ad;
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
                ad.rva = rvafunc;
                ad.va = rvafunc + (DWORD)lpImage;
                ad.name = (oftName ? lpImage + oftName : "<null>");
                bool dataApi = false;
                bool foawrdApi = false;
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
                    ad.data_api = !!isDataExport;
                    ad.forward_api = false;
                }
                else
                {
                    // 是转向函数，设定转向信息
                    Vlog("redirectApi: " << lpImage + rvafunc);
                    ad.forward_api = true;
                }
                pbModuleApis.apis.push_back(ad);
            }
        }
    }
    Vlog("[CollectModuleInfo] exit.");
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
        PipeDefine::Msg_ModuleApis pbModuleApis;
        CollectModuleInfo((HMODULE)me32.modBaseAddr, me32.szModule, me32.szExePath, pbModuleApis);

        auto content = pbModuleApis.Serial();
        PipeLine::msPipe.Send(PipeDefine::Pipe_Req_ModuleApiList, content);
        PipeDefine::MsgAck recv_type;
        content.clear();
        PipeLine::msPipe.Recv(recv_type, content);
        PipeDefine::Msg_ApiFilter filter;
        filter.Unserial(content);
        Vlog("[HookLoadedModules] reply filter count: " << std::count_if(filter.apis.begin(), filter.apis.end(), [](PipeDefine::Msg_ApiFilter::Api& a) { return a.filter; }));

        HookModuleExportTable((HMODULE)me32.modBaseAddr);

    } while (param->f_Module32Next(hModuleSnap, &me32));

    param->f_CloseHandle(hModuleSnap);
}

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

void GetModules()
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
}

void GetApis()
{
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
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
    param->f_HeapCreate = (FN_HeapCreate)param->f_GetProcAddress((HMODULE)param->kernel32, "HeapCreate");
    param->f_HeapAlloc = (FN_HeapAlloc)param->f_GetProcAddress((HMODULE)param->kernel32, "HeapAlloc");
    param->f_HeapFree = (FN_HeapFree)param->f_GetProcAddress((HMODULE)param->kernel32, "HeapFree");
    param->f_GetProcessHeap = (FN_GetProcessHeap)param->f_GetProcAddress((HMODULE)param->kernel32, "GetProcessHeap");
    param->f_CreateFileA = (FN_CreateFileA)param->f_GetProcAddress((HMODULE)param->kernel32, "CreateFileA");
    param->f_ReadFile = (FN_ReadFile)param->f_GetProcAddress((HMODULE)param->kernel32, "ReadFile");
    param->f_WriteFile = (FN_WriteFile)param->f_GetProcAddress((HMODULE)param->kernel32, "WriteFile");
    param->f_WaitNamedPipeA = (FN_WaitNamedPipeA)param->f_GetProcAddress((HMODULE)param->kernel32, "WaitNamedPipeA");
    param->f_SetNamedPipeHandleState = (FN_SetNamedPipeHandleState)param->f_GetProcAddress((HMODULE)param->kernel32, "SetNamedPipeHandleState");
    param->f_GetLastError = (FN_GetLastError)param->f_GetProcAddress((HMODULE)param->kernel32, "GetLastError");
}

void BuildPipe()
{
    Vlog("[BuildPipe]");
    PipeLine::msPipe.ConnectServer();
}

void DebugMessage()
{
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;

    wchar_t buffer[MAX_PATH] = L"User32.dll";
    UNICODE_STRING name = { 0 };
    name.Length = wcslen(buffer) * sizeof(wchar_t);
    name.Buffer = buffer;
    name.MaximumLength = sizeof(buffer);
    HANDLE hUser32 = 0;
    NTSTATUS status = param->f_LdrLoadDll(0, 0, &name, &hUser32);
    FN_MessageBoxA pMessageBox = (FN_MessageBoxA)param->f_GetProcAddress((HMODULE)hUser32, "MessageBoxA");
    char buf[32];
    sprintf_s(buf, sizeof(buf), "pid: %#x", param->dwProcessId);
    pMessageBox(0, "I'm here", buf, MB_ICONINFORMATION);

    PipeDefine::Msg_Init m;
    m.dummy = 0xaa55ccdd;
    auto content = m.Serial();
    PipeLine::msPipe.Send(PipeDefine::Pipe_Req_Inited, content);
    PipeDefine::MsgAck recv_type;
    content.clear();
    PipeLine::msPipe.Recv(recv_type, content);
    m.Unserial(content);
    Vlog("[DebugMessage] dummy: " << (LPVOID)m.dummy);
}

DWORD WINAPI Recover(LPVOID pv)
{
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;

    Vlog("[Recover]");

    HANDLE hT = param->f_OpenThread(THREAD_ALL_ACCESS, FALSE, param->dwThreadId);
    param->f_SuspendThread(hT);
    param->f_SetThreadContext(hT, &param->ctx);
    param->f_ResumeThread(hT);
    param->f_CloseHandle(hT);
    return 0;
}

void ContinueExe()
{
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
    param->f_CreateThread(0, 0, Recover, 0, 0, 0);
    while (1) {}
}

void Entry()
{
    GetModules();
    GetApis();
    Allocator::InitAllocator();
    BuildPipe();
    DebugMessage();
    HookLoadedModules();
    ContinueExe();
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

