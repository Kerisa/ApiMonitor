
#include <array>
#include <list>
#include <map>
#include <vector>
#include <set>
#include <Windows.h>
#include "def.h"
#include "allocator.h"
#include "pipemessage.h"
#include "hookroutine.h"


using Allocator::string;

PARAM* g_Param;

#define THREAD_ALL_ACCESS         (STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF) // MASK: 0x1FFFFF

__declspec(naked) intptr_t GetCurThreadId()
{
    __asm {
        mov eax,dword ptr fs:[00000018h]
        mov eax,dword ptr [eax+24h]
        ret
    }
}


class HookManager
{
    std::set<LPVOID, std::less<LPVOID>, Allocator::allocator<LPVOID>> mHookedModule;
    std::set<intptr_t, std::less<intptr_t>, Allocator::allocator<intptr_t>> mTempStopHookThread;
    LPVOID mLock{ 0 };

    void Lock()
    {
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        __declspec(align(16)) LARGE_INTEGER li;
        li.QuadPart = -10000;    // 1ms
        while (_InlineInterlockedExchangePointer(&mLock, (LPVOID)TRUE) == (LPVOID)TRUE)
            param->f_NtDelayExecution(FALSE, &li);
    }

    void ReleaseLock()
    {
        _InlineInterlockedExchangePointer(&mLock, FALSE);
    }

public:
    bool AppendHookedModule(HMODULE hmod)
    {
        Lock();
        auto result = mHookedModule.insert(hmod);        
        ReleaseLock();
        return result.second;
    }

    void RemoveHookedModule(HMODULE hmod)
    {
        Lock();
        mHookedModule.erase(hmod);
        ReleaseLock();
    }

    bool IsModuleAlreadyHooked(HMODULE hmod)
    {
        Lock();
        bool b = (mHookedModule.find(hmod) != mHookedModule.end());
        ReleaseLock();
        return b;
    }

    void StopHookForThread(intptr_t tid)
    {
        Lock();
        auto result = mTempStopHookThread.insert(tid);
        ReleaseLock();
    }

    bool IsThreadAlreadyStoppedHook(intptr_t tid)
    {
        Lock();
        bool b = (mTempStopHookThread.find(tid) != mTempStopHookThread.end());
        ReleaseLock();
        return b;
    }

    void ResumeHookForThread(intptr_t tid)
    {
        Lock();
        mTempStopHookThread.erase(tid);
        ReleaseLock();
    }
};

HookManager* g_HookManager;


void ProcessCmd(const PipeDefine::Message* msg);

class PipeLine
{
public:
    static PipeLine* msPipe;

    typedef std::vector<char, Allocator::allocator<char>> MsgStream;
    typedef std::list<MsgStream, Allocator::allocator<MsgStream>> ThreadMsgList;
    typedef std::map<DWORD, ThreadMsgList, std::less<DWORD>, Allocator::allocator<std::pair<const DWORD, ThreadMsgList>>> ThreadMsgMap;
    ThreadMsgMap*       mMsgReadBuffer{ nullptr };
    MsgStream*          mMsgWriteBuffer{ nullptr };
    CRITICAL_SECTION    csRead;
    CRITICAL_SECTION    csWrite;
    HANDLE              mPipe{ INVALID_HANDLE_VALUE };
    HANDLE              mReadThreadHandle{ NULL };
    HANDLE              mWriteThreadHandle{ NULL };
    bool                mStopWorkingThread{ false };
    bool                mThreadLockInited{ false };

    struct Lock
    {
        Lock(CRITICAL_SECTION* pcs, bool use)
        {
            PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
            mUse = use;
            mCS = pcs;
            if (use)
                param->f_RtlEnterCriticalSection(pcs);
        }
        ~Lock()
        {
            PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
            if (mUse)
                param->f_RtlLeaveCriticalSection(mCS);
        }

        bool mUse{ false };
        CRITICAL_SECTION* mCS{ nullptr };
    };

    struct TryLock
    {
        TryLock(CRITICAL_SECTION* pcs)
        {
            PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
            mCS = pcs;
            mEnter = param->f_RtlTryEnterCriticalSection(pcs);
        }
        bool IsEntered() { return mEnter; }
        ~TryLock()
        {
            PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
            if (mEnter)
                param->f_RtlLeaveCriticalSection(mCS);
        }

        bool mEnter{ false };
        CRITICAL_SECTION* mCS{ nullptr };
    };

    PipeLine()
    {
        mMsgReadBuffer = (ThreadMsgMap*)Allocator::Malloc(sizeof(ThreadMsgMap));
        new (mMsgReadBuffer) ThreadMsgMap();
        mMsgWriteBuffer = (MsgStream*)Allocator::Malloc(sizeof(MsgStream));
        new (mMsgWriteBuffer) MsgStream();
        mWriteThreadHandle = NULL;
        mReadThreadHandle = NULL;
    }

    bool ConnectServer()
    {
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        int busyRetry = 5;
        Vlog("[PipeLine::ConnectServer]");
        char piepeName[256] = { 0 };
        sprintf_s(piepeName, sizeof(piepeName), PipeDefine::PIPE_NAME_TEMPLATE, param->dwProcessId);
        while (busyRetry--)
        {
            mPipe = param->f_CreateFileA(piepeName, GENERIC_READ | GENERIC_WRITE,
                0, NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL
            );
            if (mPipe != INVALID_HANDLE_VALUE)
                break;

            if (param->f_GetLastError() != ERROR_PIPE_BUSY)
            {
                Vlog("[PipeLine::ConnectServer] Could not open pipe. GLE: " << param->f_GetLastError());
                return false;
            }

            if (!param->f_WaitNamedPipeA(piepeName, NMPWAIT_USE_DEFAULT_WAIT))
            {
                Vlog("[PipeLine::ConnectServer] Could not open pipe: 20 second wait timed out.");
                return false;
            }
        }

        DWORD dwMode = PIPE_READMODE_BYTE;
        if (!param->f_SetNamedPipeHandleState(mPipe, &dwMode, NULL, NULL))
        {
            Vlog("[PipeLine::ConnectServer] SetNamedPipeHandleState failed. GLE: " << param->f_GetLastError());
            return false;
        }

        Vlog("[PipeLine::ConnectServer] connected. " << mPipe);
        return mPipe != INVALID_HANDLE_VALUE;
    }

    bool CreateWorkThread()
    {
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        param->f_RtlInitializeCriticalSection(&csRead);
        param->f_RtlInitializeCriticalSection(&csWrite);
        HANDLE ThreadHandle = NULL;
        param->f_NtCreateThreadEx(&mWriteThreadHandle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)WriteThread, 0, FALSE, NULL, NULL, NULL, NULL);
        param->f_NtCreateThreadEx(&mReadThreadHandle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)ReadThread, 0, FALSE, NULL, NULL, NULL, NULL);
        Vlog("[PipeLine::CreateWorkThread] read-thread: " << mReadThreadHandle << ", write-thread: " << mWriteThreadHandle);
        mThreadLockInited = true;
        return true;
    }

    void StopWorkingThread()
    {
        mStopWorkingThread = true;
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        param->f_CloseHandle(mWriteThreadHandle);
        param->f_CloseHandle(mReadThreadHandle);
        mWriteThreadHandle = NULL;
        mReadThreadHandle = NULL;
    }

    bool Send(PipeDefine::PipeMsg type, const std::vector<char, Allocator::allocator<char>> & content)
    {
        // 尚未建立连接时将数据放在缓冲区中等待发送
        if (mPipe == INVALID_HANDLE_VALUE)
        {
            Vlog("[PipeLine::Send] pipe not ready.");
        }

        DWORD dummy = 0;
        std::vector<char, Allocator::allocator<char>> m(PipeDefine::Message::HeaderLength);
        PipeDefine::Message* ptr = (PipeDefine::Message*)m.data();
        ptr->type = type;
        ptr->tid = GetCurThreadId();
        ptr->ContentSize = content.size();
        m.insert(m.end(), content.begin(), content.end());
        Vlog("[PipeLine::Send] enqueue msg type: " << type << ", size: " << m.size());

        {
            Lock lk(&csWrite, mThreadLockInited);
            mMsgWriteBuffer->insert(mMsgWriteBuffer->end(), m.begin(), m.end());
        }

        if (mWriteThreadHandle == NULL || mStopWorkingThread)
        {
            WriteThread((LPVOID)1);
        }
        return true;
    }

    bool Recv(PipeDefine::PipeMsg & type, std::vector<char, Allocator::allocator<char>> & content)
    {
        if (mPipe == INVALID_HANDLE_VALUE)
        {
            Vlog("[PipeLine::Recv] pipe not ready.");
            return false;
        }

        Vlog("[PipeLine::Recv] try to receive a msg...");
        const DWORD tid = GetCurThreadId();
        bool wait = true;
        while (wait)
        {
            {
                Lock lk(&csRead, mThreadLockInited);
                ThreadMsgList& msgL = (*mMsgReadBuffer)[tid];
                if (!msgL.empty())
                {
                    MsgStream& m = msgL.front();
                    PipeDefine::Message* ptr = (PipeDefine::Message*)m.data();
                    type = ptr->type;
                    content.assign(ptr->Content, ptr->Content + ptr->ContentSize);
                    msgL.pop_front();
                    wait = false;
                }
            }

            if (wait)
            {
                if (mReadThreadHandle == NULL || mStopWorkingThread)
                {
                    ReadThread((LPVOID)1);
                }
            }
        }
        Vlog("[PipeLine::Recv] msg type: " << type << ", size: " << content.size());
        return true;
    }

    static DWORD WINAPI ReadThread(LPVOID pv)
    {
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        std::vector<char, Allocator::allocator<char>> tmpBuffer(1024 * 1024);
        size_t partialMsgSize = 0;
        bool runOnce = ((int)pv == 1);
        Vlog("[PipeLine::ReadThread] enter, run once: " << runOnce);
        do
        {
RETRY_READ:
            DWORD bytesRead = 0;
            BOOL ret = param->f_ReadFile(msPipe->mPipe, tmpBuffer.data() + partialMsgSize, tmpBuffer.size() - partialMsgSize, &bytesRead, NULL);
            if (!ret)
            {
                Vlog("[PipeLine::ReadThread] pipe read header failed, err: " << param->f_GetLastError());
                break;
            }
            if (bytesRead == 0)
            {
                if (!runOnce)
                    continue;
                else
                {
                    Vlog("[PipeLine::ReadThread] 0 bytes read, err: " << param->f_GetLastError());
                    goto RETRY_READ;
                }
            }
            partialMsgSize += bytesRead;
            Vlog("[PipeLine::ReadThread] read bytes: " << bytesRead);

            // 解析
            const intptr_t totalBytes = partialMsgSize;
            PipeDefine::Message* ptr = (PipeDefine::Message*)tmpBuffer.data();
            while ((intptr_t)ptr - (intptr_t)tmpBuffer.data() < totalBytes && partialMsgSize > 0)
            {
                if (partialMsgSize < PipeDefine::Message::HeaderLength || partialMsgSize < ptr->ContentSize + PipeDefine::Message::HeaderLength)
                {
                    Vlog("[PipeLine::ReadThread] message too short, size: " << partialMsgSize << ", err: " << param->f_GetLastError());
                    break;
                }
                if (ptr->type < 0 || ptr->type >= PipeDefine::Pipe_Msg_Total)
                {
                    Vlog("[PipeLine::ReadThread] error msg type, message may corrupted, type: " << ptr->type << ", body size: " << ptr->ContentSize);
                    break;
                }

                if (ptr->tid != -1)
                {
                    Vlog("[PipeLine::ReadThread] enqueue msg: " << ptr->type << ", length: " << ptr->ContentSize);
                    {
                        Lock lk(&msPipe->csRead, msPipe->mThreadLockInited);
                        ThreadMsgList& msgV = (*msPipe->mMsgReadBuffer)[ptr->tid];
                        msgV.push_back(MsgStream((char*)ptr, (char*)ptr + ptr->ContentSize + PipeDefine::Message::HeaderLength));
                    }
                }
                else
                {
                    // 指令
                    ProcessCmd(ptr);
                }
                const size_t msgSize = ptr->ContentSize + PipeDefine::Message::HeaderLength;
                partialMsgSize -= msgSize;
                ptr = (PipeDefine::Message*)((size_t)ptr + msgSize);
            }
        } while (!runOnce && !msPipe->mStopWorkingThread);
        Vlog("[PipeLine::ReadThread] exit.");
        return 0;
    }

    static DWORD WINAPI WriteThread(LPVOID pv)
    {
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        bool runOnce = ((int)pv == 1);
        Vlog("[PipeLine::WriteThread] enter, run once: " << runOnce);
        do
        {
            if (msPipe->mPipe == INVALID_HANDLE_VALUE)
            {
                Vlog("[PipeLine::WriteThread] pipe not ready.");
                return 1;
            }

            {
                Lock lk(&msPipe->csWrite, msPipe->mThreadLockInited);
                if (!msPipe->mMsgWriteBuffer->empty())
                {
                    DWORD dummy = 0;
                    BOOL ret = param->f_WriteFile(msPipe->mPipe, msPipe->mMsgWriteBuffer->data(), msPipe->mMsgWriteBuffer->size(), &dummy, NULL);
                    if (!ret)
                        Vlog("[PipeLine::WriteThread] result: " << ret << ", bytes written: " << dummy << ", err: " << param->f_GetLastError());
                    msPipe->mMsgWriteBuffer->clear();
                }
            }
            __declspec(align(16)) LARGE_INTEGER li;
            li.QuadPart = -10000;    // 1ms
            param->f_NtDelayExecution(FALSE, &li);
        } while (!runOnce && !msPipe->mStopWorkingThread);
        Vlog("[PipeLine::WriteThread] exit.");
        return 0;
    }
};
PipeLine* PipeLine::msPipe;

class HookEntries
{
public:
    static HookEntries msEntries;
    struct Entry
    {
        struct Param
        {
            static constexpr DWORD FLAG_BREAK_NEXT_TIME              = 1 << 0;
            static constexpr DWORD FLAG_BREAK_WHEN_CALL_FROM         = 1 << 1;
            static constexpr DWORD FLAG_BREAK_WHEN_REACH_INVOKE_TIME = 1 << 2;
            static constexpr DWORD FLAG_BREAK_ALWAYS                 = 1 << 3;
            static constexpr DWORD FLAG_CLEAR_BP_NEXT_TIME           = 1 << 4;
            static constexpr DWORD FLAG_CLEAR_BP_ALWAYS              = 1 << 5;
            static constexpr DWORD FLAG_CLEAR_BP_CALL_FROM           = 1 << 6;
            static constexpr DWORD FLAG_CLEAR_BP_REACH_INVOKE_TIME   = 1 << 7;
            long     mInvokeCount{ 0 };
            DWORD    mFlag{ 0 };
            long     mBreakReachInvokeTime{ 0 };
            LONG_PTR mBreakCallFromAddr{ 0 };
        };
        static constexpr size_t ByteCodeLength = 40;
        typedef void (__stdcall * FN_HookFunction)(uint32_t self_index, ULONG_PTR addr_of_call_from_addr);
        uint32_t                mSelfIndex;
        char*                   mBytesCode;
        string                  mModuleName;
        string                  mFuncName;
        Param                   mParams;
        FN_HookFunction         mHookFunction;
        uint64_t                mOriginalVA;

        Entry() { mBytesCode = (char*)Allocator::MallocExe(ByteCodeLength); }

        void Reset(uint32_t index)
        {
            mHookFunction = CommonHookFunction;
            mSelfIndex = index;
            memset(mBytesCode, 0, ByteCodeLength);
            mModuleName.clear();
            mFuncName.clear();
        }
    };
    static long GetGlobalId()
    {
        static volatile long id = 0;
        return _InlineInterlockedAdd(&id, 1);
    }
    static void __stdcall CommonHookFunction(uint32_t self_index, ULONG_PTR addr_of_call_from_addr)
    {
        LPVOID call_from = *(LPVOID*)addr_of_call_from_addr;
        Entry* e = msEntries.GetEntry(self_index);
        Vlog("[HookEntries::CommonHookFunction] entry: " << e
            << ", func name: " << (e ? e->mFuncName.c_str() : "<idx error>")
            << ", call from: " << call_from << ", invoke time: " << (e ? e->mParams.mInvokeCount : -1) << ", flag: " << (e ? e->mParams.mFlag : -1));
        
        if (e)
        {
            _InlineInterlockedAdd(&e->mParams.mInvokeCount, 1);
            PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
            PipeDefine::msg::ApiInvoked msgApiInvoke;
            msgApiInvoke.module_name = e->mModuleName.c_str();
            msgApiInvoke.api_name = e->mFuncName.c_str();
            msgApiInvoke.times = e->mParams.mInvokeCount;
            msgApiInvoke.call_from = (long long)*(LPVOID*)addr_of_call_from_addr;
            msgApiInvoke.raw_args[0] = (unsigned long long)*((LPVOID*)addr_of_call_from_addr + 1);
            msgApiInvoke.raw_args[1] = (unsigned long long)*((LPVOID*)addr_of_call_from_addr + 2);
            msgApiInvoke.raw_args[2] = (unsigned long long)*((LPVOID*)addr_of_call_from_addr + 3);

            if (e->mFuncName == "ExitProcess")
            {
                // 临近退出，线程不再调度
                PipeLine::msPipe->mStopWorkingThread = true;
            }

            // 清除断点
            if (e->mParams.mFlag & Entry::Param::FLAG_CLEAR_BP_NEXT_TIME)
            {
                e->mParams.mFlag &= ~Entry::Param::FLAG_CLEAR_BP_NEXT_TIME;
                e->mParams.mFlag &= ~Entry::Param::FLAG_BREAK_NEXT_TIME;
            }
            if (e->mParams.mFlag & Entry::Param::FLAG_CLEAR_BP_CALL_FROM)
            {
                e->mParams.mFlag &= ~Entry::Param::FLAG_CLEAR_BP_CALL_FROM;
                e->mParams.mFlag &= ~Entry::Param::FLAG_BREAK_WHEN_CALL_FROM;
                e->mParams.mBreakCallFromAddr = 0;
            }
            if (e->mParams.mFlag & Entry::Param::FLAG_CLEAR_BP_REACH_INVOKE_TIME)
            {
                e->mParams.mFlag &= ~Entry::Param::FLAG_CLEAR_BP_REACH_INVOKE_TIME;
                e->mParams.mFlag &= ~Entry::Param::FLAG_BREAK_WHEN_REACH_INVOKE_TIME;
                e->mParams.mBreakReachInvokeTime = 0;
            }

            // 触发断点
            if (e->mParams.mFlag & Entry::Param::FLAG_BREAK_NEXT_TIME)
            {
                e->mParams.mFlag &= ~Entry::Param::FLAG_BREAK_NEXT_TIME;
                Vlog("[CommonHookFunction] int 3(next)");
                msgApiInvoke.wait_reply = true;
                msgApiInvoke.secret = GetGlobalId();
                //__asm int 3
            }
            if (e->mParams.mFlag & Entry::Param::FLAG_BREAK_ALWAYS)
            {
                // 不清除 flag
                Vlog("[CommonHookFunction] int 3(always)");
                msgApiInvoke.wait_reply = true;
                msgApiInvoke.secret = GetGlobalId();
                //__asm int 3
            }
            if ((e->mParams.mFlag & Entry::Param::FLAG_BREAK_WHEN_CALL_FROM) && call_from == (LPVOID)e->mParams.mBreakCallFromAddr)
            {
                e->mParams.mFlag &= ~Entry::Param::FLAG_BREAK_WHEN_CALL_FROM;
                Vlog("[CommonHookFunction] int 3(addr)");
                msgApiInvoke.wait_reply = true;
                msgApiInvoke.secret = GetGlobalId();
                //__asm int 3
            }
            if ((e->mParams.mFlag & Entry::Param::FLAG_BREAK_WHEN_REACH_INVOKE_TIME) && e->mParams.mInvokeCount == e->mParams.mBreakReachInvokeTime)
            {
                e->mParams.mFlag &= ~Entry::Param::FLAG_BREAK_WHEN_REACH_INVOKE_TIME;
                Vlog("[CommonHookFunction] int 3(time)");
                msgApiInvoke.wait_reply = true;
                msgApiInvoke.secret = GetGlobalId();
                //__asm int 3
            }
            auto content = msgApiInvoke.Serial();
            PipeLine::msPipe->Send(PipeDefine::Pipe_C_Req_ApiInvoked, content);

            if (msgApiInvoke.wait_reply)
            {
                PipeDefine::PipeMsg type;
                PipeLine::msPipe->Recv(type, content);
                PipeDefine::msg::ApiInvokedReply rly;
                rly.Unserial(content);
                Vlog("[HookEntries::CommonHookFunction] reply: " << rly.secret);
            }
        }
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


void ProcessCmd(const PipeDefine::Message* msg)
{
    Vlog("[ProcessCmd] server cmd: " << msg->type);
    switch (msg->type)
    {
    case PipeDefine::Pipe_S_Req_SuspendProcess:
        break;

    case PipeDefine::Pipe_S_Req_ResumeProcess:
        break;

    case PipeDefine::Pipe_S_Req_SetBreakCondition: {
        PipeDefine::msg::SetBreakCondition sbc;
        PipeLine::MsgStream content(msg->Content, msg->Content + msg->ContentSize);
        sbc.Unserial(content);
        for (size_t i = 0; ; ++i)
        {
            HookEntries::Entry* e = HookEntries::msEntries.GetEntry(i);
            if (!e)
                break;
            if (e->mOriginalVA == sbc.func_addr)
            {
                Vlog("[ProcessCmd] found func va: " << e->mOriginalVA << "entry: " << e);
                if (sbc.flags & PipeDefine::msg::SetBreakCondition::FLAG_BC_CALL_FROM)
                {
                    e->mParams.mBreakCallFromAddr = sbc.call_from;
                    e->mParams.mFlag |= HookEntries::Entry::Param::FLAG_BREAK_WHEN_CALL_FROM;
                }
                if (sbc.flags & PipeDefine::msg::SetBreakCondition::FLAG_BC_INVOKE_TIME)
                {
                    e->mParams.mBreakReachInvokeTime = sbc.invoke_time;
                    e->mParams.mFlag |= HookEntries::Entry::Param::FLAG_BREAK_WHEN_REACH_INVOKE_TIME;
                }
                if (sbc.flags & PipeDefine::msg::SetBreakCondition::FLAG_BC_NEXT_TIME)
                {
                    e->mParams.mFlag |= HookEntries::Entry::Param::FLAG_BREAK_NEXT_TIME;
                }
                if (sbc.flags & PipeDefine::msg::SetBreakCondition::FLAG_BC_ALWAYS)
                {
                    e->mParams.mFlag |= HookEntries::Entry::Param::FLAG_BREAK_ALWAYS;
                }
                break;
            }
        }
        break;
    }
    }
}


ULONG_PTR AddHookRoutine(const string& modname, HMODULE hmod, PVOID oldEntry, PVOID oldRvaPtr, const char* funcName, const PipeDefine::msg::ApiFilter::Api* filter)
{
    Vlog("[AddHookRoutine] module: " << hmod << ", name: " << funcName << ", entry: " << oldEntry << ", rva: " << (LPVOID)*(PDWORD)oldRvaPtr);
    HookEntries::Entry* e = HookEntries::msEntries.AddEntry();
    if (!e)
    {
        Vlog("[AddHookRoutine] add new entry failed, skip");
        return 0;
    }
    e->mModuleName.assign(modname);
    e->mFuncName = funcName;
    e->mOriginalVA = (ULONG_PTR)hmod + (ULONG_PTR)*(PDWORD)oldRvaPtr;

    // 设置断点信息
    if (filter && filter->func_addr == (long long)oldEntry)
    {
        if (filter->IsBreakCallFrom())
        {
            Vlog("[AddHookRoutine] break when call from " << filter->call_from);
            e->mParams.mBreakCallFromAddr = filter->call_from;
            e->mParams.mFlag |= HookEntries::Entry::Param::FLAG_BREAK_WHEN_CALL_FROM;
        }
        if (filter->IsBreakInvokeTime())
        {
            Vlog("[AddHookRoutine] break when reach time " << filter->invoke_time);
            e->mParams.mBreakReachInvokeTime = filter->invoke_time;
            e->mParams.mFlag |= HookEntries::Entry::Param::FLAG_BREAK_WHEN_REACH_INVOKE_TIME;
        }
        if (filter->IsBreakNextTime())
        {
            Vlog("[AddHookRoutine] break at next call");
            e->mParams.mFlag |= HookEntries::Entry::Param::FLAG_BREAK_NEXT_TIME;
        }
        if (filter->IsBreakALways())
        {
            Vlog("[AddHookRoutine] break always");
            e->mParams.mFlag |= HookEntries::Entry::Param::FLAG_BREAK_ALWAYS;
        }
    }

    if (strcmp(funcName, "LdrLoadDll"))
    {
        //
        // push eax
        // push edx
        // push ecx
        // mov ecx, esp             ; <--- original return addr as call from addr
        // add ecx, c
        // push ecx
        // push entry_index
        // push continue_offset     ; <--- new return addr
        // push hook_func
        // ret
        // pop ecx                  ; <--- here continue_offset
        // pop edx
        // pop eax
        // push original_func
        // ret
        //

        e->mBytesCode[0] = '\x50';
        e->mBytesCode[1] = '\x52';
        e->mBytesCode[2] = '\x51';
        e->mBytesCode[3] = '\x8b';
        e->mBytesCode[4] = '\xcc';
        e->mBytesCode[5] = '\x83';
        e->mBytesCode[6] = '\xc1';
        e->mBytesCode[7] = '\x0c';
        e->mBytesCode[8] = '\x51';
        e->mBytesCode[9] = '\x68';
        *(ULONG_PTR*)&e->mBytesCode[10] = (ULONG_PTR)e->mSelfIndex;
        e->mBytesCode[14] = '\x68';
        *(ULONG_PTR*)&e->mBytesCode[15] = (ULONG_PTR)&e->mBytesCode[25];
        e->mBytesCode[19] = '\x68';
        *(ULONG_PTR*)&e->mBytesCode[20] = (ULONG_PTR)e->mHookFunction;
        e->mBytesCode[24] = '\xc3';
        e->mBytesCode[25] = '\x59';
        e->mBytesCode[26] = '\x5a';
        e->mBytesCode[27] = '\x58';
        e->mBytesCode[28] = '\x68';
        *(ULONG_PTR*)&e->mBytesCode[29] = (ULONG_PTR)oldEntry;
        e->mBytesCode[33] = '\xc3';
        e->mBytesCode[34] = '\xcc';
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

void HookModuleExportTable(HMODULE hmod, const string& modname, const string& modpath, const PipeDefine::msg::ApiFilter& filter)
{
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
    bool apply_filter = (filter.module_name == modname);
    Vlog("[HookModuleExportTable] enter, hmod: " << (LPVOID)hmod << ", apply filter: " << apply_filter);

    size_t count = std::count_if(filter.apis.begin(), filter.apis.end(), [](const PipeDefine::msg::ApiFilter::Api& api) {
        return api.IsFilter();
    });
    if (count == 0)
    {
        Vlog("[HookModuleExportTable] hook count == 0, exit");
        return;
    }

    std::map<long long, PipeDefine::msg::ApiFilter::Api, std::less<long long>, Allocator::allocator<std::pair<long long, PipeDefine::msg::ApiFilter::Api>>> filter_apis;
    if (apply_filter)
    {
        Vlog("[HookModuleExportTable] build filter api set");
        for (size_t i = 0; i < filter.apis.size(); ++i)
        {
            filter_apis.insert(std::make_pair(filter.apis[i].func_addr, filter.apis[i]));
        }
    }

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
    __declspec(align(16)) SIZE_T RegionSize = pExportSize;
    __declspec(align(16)) LPVOID BaseAddress = 0;
    param->f_NtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &RegionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    PIMAGE_EXPORT_DIRECTORY imEDNew = (PIMAGE_EXPORT_DIRECTORY)BaseAddress;
    memcpy_s(imEDNew, pExportSize, imED, pExportSize);
    DWORD delta = (char*)imEDNew - (char*)imED;
    imEDNew->AddressOfFunctions    += delta;
    imEDNew->AddressOfNames        += delta;
    imEDNew->AddressOfNameOrdinals += delta;
    PDWORD oldFunc = (PDWORD)(lpImage + imED->AddressOfFunctions);
    PDWORD newFunc = (PDWORD)(lpImage + imEDNew->AddressOfFunctions);
    for (DWORD i = 0; i < imED->NumberOfNames; ++i)
    {
        ((PDWORD)(lpImage + imEDNew->AddressOfNames))[i] += delta;
    }

    __declspec(align(16)) DWORD  oldProtect1 = 0;
    __declspec(align(16)) LPVOID baseAddr1 = oldFunc;
    __declspec(align(16)) ULONG  sizeToProtect1 = imEDNew->NumberOfFunctions * sizeof(DWORD);
    param->f_NtProtectVirtualMemory(NtCurrentProcess(), &baseAddr1, &sizeToProtect1, PAGE_READWRITE, &oldProtect1);

    Vlog("[HookModuleExportTable] replace exdisting export table, count: " << imED->NumberOfFunctions);
    char tmpFuncNameBuffer[32] = { 0 };
    PDWORD lpNames    = imED->AddressOfNames ? (PDWORD)(lpImage + imED->AddressOfNames) : 0;
    PWORD  lpOrdinals = imED->AddressOfNameOrdinals ? (PWORD)(lpImage + imED->AddressOfNameOrdinals) : 0;
    for (DWORD i = 0; i < imED->NumberOfFunctions; ++i)
    {
        if (oldFunc[i] >= exportRVA && oldFunc[i] < exportRVA + pExportSize)
        {
            Vlog("[HookModuleExportTable] skip forword function: " << (lpImage + oldFunc[i]));
            newFunc[i] += delta;
            continue;
        }

        // 查找名称
        const char* funcName = "";
        for (DWORD k = 0; k < imED->NumberOfNames; ++k)
        {
            if (lpOrdinals[k] == i)
            {
                funcName = lpImage + lpNames[k];
                break;
            }
        }
        if (funcName[0] == '\0')
        {
            sprintf_s(tmpFuncNameBuffer, sizeof(tmpFuncNameBuffer), "<ordinal %d>", i + imED->Base);
            funcName = tmpFuncNameBuffer;
        }

        bool dataExp = false;
        bool forwardApi = false;
        CheckDataExportOrForwardApi(dataExp, forwardApi, oldFunc[i], &imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT], imNH, lpImage);
        if (dataExp || forwardApi)
        {
            Vlog("[HookModuleExportTable] skip forward api or data api, name: " << funcName << ", data: " << dataExp << ", forward: " << forwardApi);
            continue;
        }

        if (strcmp(funcName, "LdrLoadDll"))
        {
            PVOID va = (PVOID)(lpImage + oldFunc[i]);
            PipeDefine::msg::ApiFilter::Api* fa = nullptr;
            if (apply_filter)
            {
                auto it = filter_apis.find((long long)va);
                if (it != filter_apis.end())
                    fa = &it->second;
            }
            bool hook = fa ? fa->IsFilter() : true;
            if (!hook)
                Vlog("[HookModuleExportTable] skip hook " << funcName << " due to filter");
            ULONG_PTR newRva = hook ? AddHookRoutine(modname, hmod, (PVOID)(lpImage + oldFunc[i]), &oldFunc[i], funcName, fa) : 0;
            if (newRva)
                newFunc[i] = newRva;
            else
                newFunc[i] = oldFunc[i];
        }
        else
        {
            Vlog("[HookModuleExportTable] skip LdrLoadDll");
            newFunc[i] = oldFunc[i];
        }
    }

    __declspec(align(16)) DWORD  oldProtect2 = 0;
    __declspec(align(16)) LPVOID baseAddr2 = &imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    __declspec(align(16)) ULONG  sizeToProtect2 = sizeof(DWORD);
    param->f_NtProtectVirtualMemory(NtCurrentProcess(), &baseAddr2, &sizeToProtect2, PAGE_READWRITE, &oldProtect2);
    imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = (DWORD)imEDNew - (DWORD)lpImage;
    if (oldProtect2 != 0)
    {
        baseAddr2 = &imNH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        sizeToProtect2 = sizeof(DWORD);
        param->f_NtProtectVirtualMemory(NtCurrentProcess(), &baseAddr2, &sizeToProtect2, oldProtect2, &oldProtect2);
    }
    Vlog("[HookModuleExportTable] finish");
    if (oldProtect1 != 0)
    {
        LPVOID baseAddr1 = oldFunc;
        ULONG  sizeToProtect1 = imEDNew->NumberOfFunctions * sizeof(DWORD);
        param->f_NtProtectVirtualMemory(NtCurrentProcess(), &baseAddr1, &sizeToProtect1, oldProtect1, &oldProtect1);
    }
}


bool DoModuleHook(HMODULE hmod, const string& _path, bool checkPipeReply)
{
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;

    const bool isNtdll = _path == "ntdll.dll";

    if (!param->bNtdllInited)
        return false;
    if (!hmod)
        return false;
    const IMAGE_DOS_HEADER* dosHeader = (const IMAGE_DOS_HEADER*)hmod;
    if (dosHeader->e_magic != 0x5a4d)
        return 0;
    if (((const IMAGE_NT_HEADERS*)((ULONG_PTR)hmod + dosHeader->e_lfanew))->Signature != 0x4550)
        return 0;
    if (g_HookManager->IsThreadAlreadyStoppedHook(GetCurThreadId()))
        return false;
    if (g_HookManager->IsModuleAlreadyHooked(hmod))
        return false;

    wchar_t wBuffer[512] = { '$' };
    UNICODE_STRING wsName;
    wsName.MaximumLength = sizeof(wBuffer);
    wsName.Buffer = wBuffer;
    wsName.Length = 0;
    param->f_LdrGetDllFullName(hmod, &wsName);

    string path = _path;
    string moduleName;
    for (int i = 0; i < wsName.Length && wsName.Buffer[i]; ++i)
        moduleName += (char)wsName.Buffer[i];
    if (moduleName.empty())
    {
        if (!path.empty())
        {
            moduleName.assign(path);
        }
        else
        {
            moduleName = GetDllNameFromExportDirectory(hmod);
            path.assign(moduleName);
        }
    }
    else
    {
        // 来自 LdrGetDllFullName 的全路径
        path.assign(moduleName);
        size_t pos = moduleName.find_last_of('\\');
        if (pos != string::npos)
            moduleName = moduleName.substr(pos + 1);
    }
    Vlog("[DoModuleHook] dll: " << moduleName.c_str() << ", base: " << (LPVOID)hmod);
    if (moduleName.empty())
        return false;

    PipeDefine::msg::ModuleApis msgModuleApis;
    CollectModuleInfo(hmod, moduleName, path, msgModuleApis);
    msgModuleApis.no_reply = !checkPipeReply;
    auto content = msgModuleApis.Serial();
    if (!isNtdll)
        PipeLine::msPipe->Send(PipeDefine::Pipe_C_Req_ModuleApiList, content);

    PipeDefine::msg::ApiFilter filter;
    if (checkPipeReply)
    {
        PipeDefine::PipeMsg recv_type;
        content.clear();
        PipeLine::msPipe->Recv(recv_type, content);
        filter.Unserial(content);
        Vlog("[DoModuleHook] reply filter count: " << std::count_if(filter.apis.begin(), filter.apis.end(), [](PipeDefine::msg::ApiFilter::Api& a) { return a.filter; }));
    }
    else
    {
        // ntdll 自行构造
        if (isNtdll)
        {
            if (param->ntdllFilterSerialDataSize > 0 && param->ntdllFilterSerialDataSize < sizeof(param->ntdllFilterSerialData))
            {
                std::vector<char, Allocator::allocator<char>> v(param->ntdllFilterSerialData, param->ntdllFilterSerialData + param->ntdllFilterSerialDataSize);
                filter.Unserial(v);
            }
        }
        else
        {
            filter.module_name = msgModuleApis.module_name;
            for (size_t i = 0; i < msgModuleApis.apis.size(); ++i)
            {
                PipeDefine::msg::ApiFilter::Api a;
                a.SetFilter();
                a.func_addr = msgModuleApis.apis[i].va;
                filter.apis.push_back(a);
            }
        }
    }

    HookModuleExportTable(hmod, moduleName, path, filter);

    g_HookManager->AppendHookedModule(hmod);
    return true;
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
        DoModuleHook((HMODULE)me32.modBaseAddr, me32.szExePath, true);
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
    //param->f_LdrLoadDll = (FN_LdrLoadDll)MiniGetFunctionAddress((ULONG_PTR)param->ntdllBase, "LdrLoadDll");
    param->f_LdrInitializeThunk = (FN_LdrInitializeThunk)MiniGetFunctionAddress((ULONG_PTR)param->ntdllBase, "LdrInitializeThunk");
    wchar_t buffer[MAX_PATH] = L"kernelbase.dll";
    UNICODE_STRING name = { 0 };
    name.Length = static_cast<USHORT>(wcslen(buffer) * sizeof(wchar_t));
    name.Buffer = buffer;
    name.MaximumLength = static_cast<USHORT>(sizeof(buffer));
    HANDLE hKernel = 0;
    NTSTATUS status = param->f_LdrLoadDll(0, 0, &name, &hKernel);
    param->kernelBase = (LPVOID)hKernel;
    param->f_GetProcAddress = (FN_GetProcAddress)MiniGetFunctionAddress((ULONG_PTR)hKernel, "GetProcAddress");
}

void GetApis(bool ntdllOnly)
{
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;

#define GET_NTDLL_API(fn) do { \
        if (!param->f_ ## fn) \
            param->f_ ## fn = (FN_ ## fn)MiniGetFunctionAddress((ULONG_PTR)param->ntdllBase, # fn); \
        if (!param->f_ ## fn) \
            throw "ntapi "# fn "not found"; \
    } while (0)

    GET_NTDLL_API(NtSuspendProcess);
    GET_NTDLL_API(NtResumeProcess);
    GET_NTDLL_API(NtAllocateVirtualMemory);
    GET_NTDLL_API(RtlCreateHeap);
    GET_NTDLL_API(RtlAllocateHeap);
    GET_NTDLL_API(RtlFreeHeap);
    GET_NTDLL_API(NtProtectVirtualMemory);
    GET_NTDLL_API(RtlInitializeCriticalSection);
    GET_NTDLL_API(RtlEnterCriticalSection);
    GET_NTDLL_API(RtlLeaveCriticalSection);
    GET_NTDLL_API(LdrGetDllFullName);
    GET_NTDLL_API(NtDelayExecution);
    GET_NTDLL_API(NtCreateThreadEx);
    GET_NTDLL_API(RtlTryEnterCriticalSection);
    //GET_NTDLL_API(NtQueryInformationFile);

    if (ntdllOnly)
        return;

    if (!param->f_GetProcAddress)
        param->f_GetProcAddress = (FN_GetProcAddress)MiniGetFunctionAddress((ULONG_PTR)param->kernelBase, "GetProcAddress");

    param->f_GetModuleHandleA = (FN_GetModuleHandleA)param->f_GetProcAddress((HMODULE)param->kernelBase, "GetModuleHandleA");
    param->f_OpenThread = (FN_OpenThread)param->f_GetProcAddress((HMODULE)param->kernelBase, "OpenThread");
    param->f_SuspendThread = (FN_SuspendThread)param->f_GetProcAddress((HMODULE)param->kernelBase, "SuspendThread");
    param->f_SetThreadContext = (FN_SetThreadContext)param->f_GetProcAddress((HMODULE)param->kernelBase, "SetThreadContext");
    param->f_ResumeThread = (FN_ResumeThread)param->f_GetProcAddress((HMODULE)param->kernelBase, "ResumeThread");
    param->f_CloseHandle = (FN_CloseHandle)param->f_GetProcAddress((HMODULE)param->kernelBase, "CloseHandle");
    param->f_OutputDebugStringA = (FN_OutputDebugStringA)param->f_GetProcAddress((HMODULE)param->kernelBase, "OutputDebugStringA");

    param->kernel32 = (LPVOID)param->f_GetModuleHandleA("kernel32.dll");
    param->f_CreateToolhelp32Snapshot = (FN_CreateToolhelp32Snapshot)param->f_GetProcAddress((HMODULE)param->kernel32, "CreateToolhelp32Snapshot");
    param->f_Module32First = (FN_Module32First)param->f_GetProcAddress((HMODULE)param->kernel32, "Module32First");
    param->f_Module32Next = (FN_Module32Next)param->f_GetProcAddress((HMODULE)param->kernel32, "Module32Next");
    param->f_GetProcessHeap = (FN_GetProcessHeap)param->f_GetProcAddress((HMODULE)param->kernel32, "GetProcessHeap");
    param->f_CreateFileA = (FN_CreateFileA)param->f_GetProcAddress((HMODULE)param->kernel32, "CreateFileA");
    param->f_ReadFile = (FN_ReadFile)param->f_GetProcAddress((HMODULE)param->kernel32, "ReadFile");
    param->f_WriteFile = (FN_WriteFile)param->f_GetProcAddress((HMODULE)param->kernel32, "WriteFile");
    param->f_WaitNamedPipeA = (FN_WaitNamedPipeA)param->f_GetProcAddress((HMODULE)param->kernel32, "WaitNamedPipeA");
    param->f_SetNamedPipeHandleState = (FN_SetNamedPipeHandleState)param->f_GetProcAddress((HMODULE)param->kernel32, "SetNamedPipeHandleState");
    param->f_GetLastError = (FN_GetLastError)param->f_GetProcAddress((HMODULE)param->kernel32, "GetLastError");
}

void BuildPipe(bool connect)
{
    Vlog("[BuildPipe] enter. connect: " << connect);
    if (!PipeLine::msPipe)
    {
        PipeLine::msPipe = (PipeLine*)Allocator::Malloc(sizeof(PipeLine));
        new (PipeLine::msPipe) PipeLine();
    }
    if (connect)
        PipeLine::msPipe->ConnectServer();
    Vlog("[BuildPipe] exit.");
}

void DebugMessage()
{
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;

    wchar_t buffer[MAX_PATH] = L"User32.dll";
    UNICODE_STRING name = { 0 };
    name.Length = static_cast<USHORT>(wcslen(buffer) * sizeof(wchar_t));
    name.Buffer = buffer;
    name.MaximumLength = static_cast<USHORT>(sizeof(buffer));
    HANDLE hUser32 = 0;
    NTSTATUS status = param->f_LdrLoadDll(0, 0, &name, &hUser32);
    FN_MessageBoxA pMessageBox = (FN_MessageBoxA)param->f_GetProcAddress((HMODULE)hUser32, "MessageBoxA");
    char buf[32];
    sprintf_s(buf, sizeof(buf), "pid: %#x", param->dwProcessId);
    pMessageBox(0, "I'm here", buf, MB_ICONINFORMATION);

    PipeDefine::msg::Init msgInit;
    msgInit.dummy = 0xaa55ccdd;
    auto content = msgInit.Serial();
    PipeLine::msPipe->Send(PipeDefine::Pipe_C_Req_Inited, content);
    PipeDefine::PipeMsg recv_type;
    content.clear();
    PipeLine::msPipe->Recv(recv_type, content);
    msgInit.Unserial(content);
    Vlog("[DebugMessage] dummy: " << (LPVOID)msgInit.dummy);
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
    HANDLE ThreadHandle = NULL;
    param->f_NtCreateThreadEx(&ThreadHandle, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), (LPTHREAD_START_ROUTINE)Recover, 0, FALSE, NULL, NULL, NULL, NULL);
    while (1) {}
}

void InitNtdllApiAndEnv()
{
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
    if (param->bNtdllInited)
        return;

    GetApis(true);
    Allocator::InitAllocator();
    g_HookManager = (HookManager*)Allocator::Malloc(sizeof(HookManager));
    new (g_HookManager) HookManager();
    BuildPipe(false);

    // 前后有依赖关系...
    param->bNtdllInited = true;
    DoModuleHook((HMODULE)param->ntdllBase, "ntdll.dll", false);
}

void InitKernelDllAndEnv()
{
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
    if (!param->bNtdllInited)
        return;
    if (param->bOthersInited)
        return;

    if (!param->kernelBase)
    {
        wchar_t buffer[MAX_PATH] = L"kernelbase.dll";
        UNICODE_STRING name = { 0 };
        name.Length = static_cast<USHORT>(wcslen(buffer) * sizeof(wchar_t));
        name.Buffer = buffer;
        name.MaximumLength = static_cast<USHORT>(sizeof(buffer));
        HANDLE hKernel = 0;
        NTSTATUS status = param->f_LdrLoadDll(0, 0, &name, &hKernel);
        param->kernelBase = (LPVOID)hKernel;
    }
    if (!param->kernel32)
    {
        wchar_t buffer[MAX_PATH] = L"kernel32.dll";
        UNICODE_STRING name = { 0 };
        name.Length = static_cast<USHORT>(wcslen(buffer) * sizeof(wchar_t));
        name.Buffer = buffer;
        name.MaximumLength = static_cast<USHORT>(sizeof(buffer));
        HANDLE hKernel = 0;
        NTSTATUS status = param->f_LdrLoadDll(0, 0, &name, &hKernel);
        param->kernel32 = (LPVOID)hKernel;
    }
    if (param->kernel32 && param->kernelBase)
    {
        GetApis(false);
        BuildPipe(true);
        param->bOthersInited = true;

        const int preLoadCount = 2;
        HMODULE preLoadAddr[preLoadCount] = { (HMODULE)param->kernelBase, (HMODULE)param->kernel32 };
        const char* preLoadName[preLoadCount] = { "kernelbase.dll", "kernel32.dll" };
        for (int i = 0; i < preLoadCount; ++i)
        {
            DoModuleHook(preLoadAddr[i], preLoadName[i], true);
        }
    }
}

NTSTATUS NTAPI HookLdrLoadDllPad(PWCHAR PathToFile, ULONG Flags, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle)
{
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
    if (g_HookManager)
        g_HookManager->StopHookForThread(GetCurThreadId());
    NTSTATUS ret = param->f_LdrLoadDll(PathToFile, Flags, ModuleFileName, ModuleHandle);
    if (g_HookManager)
        g_HookManager->ResumeHookForThread(GetCurThreadId());

    InitNtdllApiAndEnv();
    InitKernelDllAndEnv();

    Vlog("[HookLdrLoadDllPad] ret value: " << ret << ", name: " << string(ModuleFileName->Buffer, ModuleFileName->Buffer + ModuleFileName->Length) << ", base: " << *ModuleHandle);
    // for this new loaded dll
    if (ret == 0 && *ModuleHandle != param->kernel32 && *ModuleHandle != param->kernelBase)
    {
        string moduleName;
        for (int i = 0; i < ModuleFileName->Length && ModuleFileName->Buffer[i]; ++i)
            moduleName += (char)ModuleFileName->Buffer[i];
        Vlog("[HookLdrLoadDllPad] dll: " << moduleName.c_str() << ", base: " << *ModuleHandle);
        DoModuleHook((HMODULE)*ModuleHandle, moduleName, true);
    }
    else
    {
        Vlog("[HookLdrLoadDllPad] skip.");
    }
    return ret;
}

NTSTATUS WINAPI NtMapViewOfSectionPadSub(HMODULE hModule, HANDLE secHandle)
{
    PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
    if (!param->bNtdllInited)
        return 0;
    DoModuleHook((HMODULE)hModule, "", true);
    return 0;
}

NTSTATUS NTAPI NtMapViewOfSectionPad(
    HANDLE          SectionHandle,
    HANDLE          ProcessHandle,
    PVOID           *BaseAddress,
    ULONG_PTR       ZeroBits,
    SIZE_T          CommitSize,
    PLARGE_INTEGER  SectionOffset,
    PSIZE_T         ViewSize,
    LONG            InheritDisposition, // enum SECTION_INHERIT
    ULONG           AllocationType,
    ULONG           Win32Protect
)
{
    static_assert(PARAM::PARAM_ADDR                         == 0x20000000, "offset out of date");
    static_assert((DWORD)&((PARAM*)0)->NtMapViewOfSectionServerId == 0x20, "offset out of date");
    static_assert((DWORD)&((PARAM*)0)->f_Wow64SystemServiceCall   == 0x24, "offset out of date");
    __asm {
        mov edx, 0x20000024
        mov edx, dword ptr [edx]
        mov eax, 0x20000020
        mov eax, dword ptr [eax]
        call edx
        cmp eax, 0
        jne SKIP
        mov eax, dword ptr [esp + 0x4]
        push eax
        mov eax, dword ptr [esp + 0x10]        // *BaseAddress
        mov eax, dword ptr [eax]
        push eax
        call NtMapViewOfSectionPadSub
SKIP:
        ret 28h
    }
}

void Entry()
{
    PipeLine::msPipe->CreateWorkThread();
    DebugMessage();
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

