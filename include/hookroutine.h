#pragma once

#include <Windows.h>
#include "def.h"
#include "allocator.h"
#include "pipemessage.h"


class SStream
{
public:
    SStream() { mBuf.resize(1024); }
    SStream& operator<<(const char* s)
    {
        if (s)
            strcat_s(mBuf.data(), mBuf.size(), s);
        else
            strcat_s(mBuf.data(), mBuf.size(), "(null passed)");
        return *this;
    }
    SStream& operator<<(const Allocator::string& s)
    {
        strcat_s(mBuf.data(), mBuf.size(), s.c_str());
        return *this;
    }
    SStream& operator<<(int i)
    {
        char buf[32];
        sprintf_s(buf, sizeof(buf), "%d", i);
        strcat_s(mBuf.data(), mBuf.size(), buf);
        return *this;
    }
    SStream& operator<<(unsigned long i)
    {
        char buf[32];
        sprintf_s(buf, sizeof(buf), "%u", i);
        strcat_s(mBuf.data(), mBuf.size(), buf);
        return *this;
    }
    SStream& operator<<(unsigned __int64 i)
    {
        char buf[32];
        sprintf_s(buf, sizeof(buf), "%llu", i);
        strcat_s(mBuf.data(), mBuf.size(), buf);
        return *this;
    }
    SStream& operator<<(__int64 i)
    {
        char buf[32];
        sprintf_s(buf, sizeof(buf), "%lld", i);
        strcat_s(mBuf.data(), mBuf.size(), buf);
        return *this;
    }
    SStream& operator<<(void* p)
    {
        char buf[32];
        sprintf_s(buf, sizeof(buf), "0x%p", p);
        strcat_s(mBuf.data(), mBuf.size(), buf);
        return *this;
    }

    SStream& operator<<(unsigned int i) { return operator<<(static_cast<unsigned long>(i)); }
    SStream& operator<<(HMODULE i) { return operator<<(static_cast<void*>(i)); }
    const char* str() const { return mBuf.data(); }
private:
    std::vector<char, Allocator::allocator<char>> mBuf;
};

//#define PRINT_DEBUG_LOG

#ifdef PRINT_DEBUG_LOG
  #define Vlog(cond) do { \
      PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR; \
      if (!param->f_OutputDebugStringA) break; \
      SStream ml; \
      ml << " [" << param->dwProcessId << "." << GetCurThreadId() << "] " << cond << "\n"; \
      param->f_OutputDebugStringA(ml.str()); \
    } while (0)
#else
  #define Vlog(cond) ((void*)0)
#endif


bool                IsMemoryReadable(LPVOID addr);
Allocator::string   GetDllNameFromExportDirectory(HMODULE hmod);
void                CheckDataExportOrForwardApi(bool& dataExp, bool& forwardApi, DWORD rvafunc, PIMAGE_DATA_DIRECTORY exportDir, PIMAGE_NT_HEADERS imNH, const char* lpImage);
void                CollectModuleInfo(HMODULE hmod, const Allocator::string& modname, const Allocator::string& modpath, PipeDefine::msg::ModuleApis& msgModuleApis);
PVOID               BuildRemoteData(HANDLE hProcess, const TCHAR* dllPath);