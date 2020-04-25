
#pragma once

#include <Windows.h>
#include <tlhelp32.h>

#define NtCurrentProcess() ( (HANDLE)(LONG_PTR) -1 )

typedef VOID (NTAPI * FN_LdrInitializeThunk)(
    ULONG Unknown1,
    ULONG Unknown2,
    ULONG Unknown3,
    ULONG Unknown4);

typedef LONG (NTAPI * PRTL_HEAP_COMMIT_ROUTINE)(
    IN PVOID Base,
    IN OUT PVOID *CommitAddress,
    IN OUT PSIZE_T CommitSize);

typedef struct _RTL_HEAP_PARAMETERS {
    ULONG Length;
    SIZE_T SegmentReserve;
    SIZE_T SegmentCommit;
    SIZE_T DeCommitFreeBlockThreshold;
    SIZE_T DeCommitTotalFreeThreshold;
    SIZE_T MaximumAllocationSize;
    SIZE_T VirtualMemoryThreshold;
    SIZE_T InitialCommit;
    SIZE_T InitialReserve;
    PRTL_HEAP_COMMIT_ROUTINE CommitRoutine;
    SIZE_T Reserved[2];
} RTL_HEAP_PARAMETERS, *PRTL_HEAP_PARAMETERS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef LONG (NTAPI * FN_LdrLoadDll)(
    PWCHAR               PathToFile,
    ULONG                Flags,
    PUNICODE_STRING      ModuleFileName,
    PHANDLE              ModuleHandle);

typedef LONG (NTAPI *FN_NtSuspendProcess)(
    HANDLE ProcessHandle);

typedef LONG (NTAPI *FN_NtResumeProcess)(
    HANDLE ProcessHandle);

typedef LONG (NTAPI * FN_NtAllocateVirtualMemory)(
    HANDLE    ProcessHandle,
    PVOID     *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T   RegionSize,
    ULONG     AllocationType,
    ULONG     Protect);

typedef PVOID (NTAPI * FN_RtlCreateHeap)(
    ULONG                Flags,
    PVOID                HeapBase,
    SIZE_T               ReserveSize,
    SIZE_T               CommitSize,
    PVOID                Lock,
    PRTL_HEAP_PARAMETERS Parameters);

typedef PVOID (NTAPI * FN_RtlAllocateHeap)(
    PVOID  HeapHandle,
    ULONG  Flags,
    SIZE_T Size);

typedef LONG (NTAPI * FN_RtlFreeHeap)(
    PVOID HeapHandle,
    ULONG Flags,
    PVOID BaseAddress);

typedef LONG (NTAPI * FN_NtProtectVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID  *BaseAddress,
    PULONG NumberOfBytesToProtect,
    ULONG  NewAccessProtection,
    PULONG OldAccessProtection);

typedef void (WINAPI * FN_RtlInitializeCriticalSection)(
    RTL_CRITICAL_SECTION* lpCriticalSection);

typedef LONG(WINAPI * FN_RtlEnterCriticalSection)(
    RTL_CRITICAL_SECTION* lpCriticalSection);

typedef void (WINAPI * FN_RtlLeaveCriticalSection)(
    RTL_CRITICAL_SECTION* lpCriticalSection);

typedef LONG (NTAPI * FN_LdrGetDllFullName)(
    PVOID DllHandle,
    PUNICODE_STRING FullDllName);

typedef LONG (NTAPI * FN_NtDelayExecution)(
    BOOLEAN              Alertable,
    PLARGE_INTEGER       Interval);

typedef LONG (NTAPI* FN_NtCreateThreadEx)(
     PHANDLE hThread,
     ACCESS_MASK DesiredAccess,
     PVOID ObjectAttributes,
     HANDLE ProcessHandle,
     PVOID lpStartAddress,
     PVOID lpParameter,
     ULONG Flags,
     SIZE_T StackZeroBits,
     SIZE_T SizeOfStackCommit,
     SIZE_T SizeOfStackReserve,
     PVOID lpBytesBuffer);

typedef BOOL (NTAPI * FN_RtlTryEnterCriticalSection)(
    RTL_CRITICAL_SECTION* crit);

typedef FARPROC(WINAPI * FN_GetProcAddress)(
    HMODULE hModule,
    LPCSTR  lpProcName);

typedef int (WINAPI * FN_MessageBoxA)(
    HWND    hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT    uType);

typedef HMODULE (WINAPI * FN_GetModuleHandleA)(
    LPCSTR lpModuleName);

typedef HANDLE(WINAPI * FN_OpenThread)(
    DWORD dwDesiredAccess,
    BOOL bInheritHandle,
    DWORD dwThreadId);

typedef DWORD(WINAPI * FN_SuspendThread)(
    HANDLE hThread);

typedef DWORD(WINAPI * FN_ResumeThread)(
    HANDLE hThread);

typedef BOOL(WINAPI * FN_SetThreadContext)(
    HANDLE hThread,
    CONTEXT* lpContext);

typedef BOOL(WINAPI * FN_CloseHandle)(
    HANDLE hObject);

typedef VOID (WINAPI * FN_OutputDebugStringA)(
    LPCSTR lpOutputString);

typedef LPVOID (WINAPI * FN_VirtualAlloc)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect);

typedef BOOL (WINAPI * FN_VirtualProtect)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flNewProtect,
    PDWORD lpflOldProtect);

typedef HANDLE (WINAPI * FN_CreateToolhelp32Snapshot)(
    DWORD dwFlags,
    DWORD th32ProcessID);

typedef BOOL (WINAPI * FN_Module32First)(
    HANDLE hSnapshot,
    tagMODULEENTRY32* lpme);

typedef BOOL(WINAPI * FN_Module32Next)(
    HANDLE hSnapshot,
    tagMODULEENTRY32* lpme);

typedef LPVOID (WINAPI * FN_HeapAlloc)(
    HANDLE hHeap,
    DWORD dwFlags,
    SIZE_T dwBytes);

typedef HANDLE(WINAPI * FN_GetProcessHeap)();

typedef BOOL (WINAPI * FN_HeapFree)(
    HANDLE hHeap,
    DWORD dwFlags,
    LPVOID lpMem);

typedef HANDLE (WINAPI * FN_HeapCreate)(
    DWORD  flOptions,
    SIZE_T dwInitialSize,
    SIZE_T dwMaximumSize);

typedef HANDLE (WINAPI * FN_CreateFileA)(
    LPCSTR                lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile);

typedef BOOL (WINAPI * FN_ReadFile)(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped);

typedef BOOL (WINAPI * FN_WriteFile)(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped);

typedef BOOL (WINAPI * FN_WaitNamedPipeA)(
    LPCSTR lpNamedPipeName,
    DWORD  nTimeOut);

typedef BOOL (WINAPI * FN_SetNamedPipeHandleState)(
    HANDLE  hNamedPipe,
    LPDWORD lpMode,
    LPDWORD lpMaxCollectionCount,
    LPDWORD lpCollectDataTimeout);

typedef DWORD (WINAPI * FN_GetLastError)();

typedef DWORD (WINAPI * FN_GetCurrentThreadId)();

struct PARAM
{
    static constexpr DWORD PARAM_ADDR = 0x20000000;

    LPVOID ntdllBase;
    LPVOID kernelBase;
    LPVOID kernel32;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
    HANDLE NormalHeapHandle;
    HANDLE ExecuteHeapHandle;

    bool   bNtdllInited;
    bool   bOthersInited;

    DWORD  NtMapViewOfSectionServerId;
    LPVOID f_Wow64SystemServiceCall;

    // ntdll
    FN_LdrInitializeThunk           f_LdrInitializeThunk;
    FN_LdrLoadDll                   f_LdrLoadDll;
    FN_NtSuspendProcess             f_NtSuspendProcess;
    FN_NtResumeProcess              f_NtResumeProcess;
    FN_NtAllocateVirtualMemory      f_NtAllocateVirtualMemory;
    FN_RtlCreateHeap                f_RtlCreateHeap;
    FN_RtlAllocateHeap              f_RtlAllocateHeap;
    FN_RtlFreeHeap                  f_RtlFreeHeap;
    FN_NtProtectVirtualMemory       f_NtProtectVirtualMemory;
    FN_RtlInitializeCriticalSection f_RtlInitializeCriticalSection;
    FN_RtlEnterCriticalSection      f_RtlEnterCriticalSection;
    FN_RtlLeaveCriticalSection      f_RtlLeaveCriticalSection;
    FN_LdrGetDllFullName            f_LdrGetDllFullName;
    FN_NtDelayExecution             f_NtDelayExecution;
    FN_NtCreateThreadEx             f_NtCreateThreadEx;
    FN_RtlTryEnterCriticalSection   f_RtlTryEnterCriticalSection;

    // kernelbase
    FN_GetModuleHandleA          f_GetModuleHandleA;
    FN_GetProcAddress            f_GetProcAddress;
    FN_OpenThread                f_OpenThread;
    FN_SuspendThread             f_SuspendThread;
    FN_SetThreadContext          f_SetThreadContext;
    FN_ResumeThread              f_ResumeThread;
    FN_CloseHandle               f_CloseHandle;
    FN_OutputDebugStringA        f_OutputDebugStringA;

    // kernel32
    FN_CreateToolhelp32Snapshot  f_CreateToolhelp32Snapshot;
    FN_Module32First             f_Module32First;
    FN_Module32Next              f_Module32Next;
    FN_GetProcessHeap            f_GetProcessHeap;
    FN_CreateFileA               f_CreateFileA;
    FN_ReadFile                  f_ReadFile;
    FN_WriteFile                 f_WriteFile;
    FN_WaitNamedPipeA            f_WaitNamedPipeA;
    FN_SetNamedPipeHandleState   f_SetNamedPipeHandleState;
    FN_GetLastError              f_GetLastError;


    CONTEXT ctx;
    char ntdllFilterSerialData[90000];
};
