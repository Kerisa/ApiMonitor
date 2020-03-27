
#include <tlhelp32.h>

typedef VOID (NTAPI * FN_LdrInitializeThunk)(
    ULONG Unknown1,
    ULONG Unknown2,
    ULONG Unknown3,
    ULONG Unknown4);

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef NTSTATUS(NTAPI * FN_LdrLoadDll)(
    PWCHAR               PathToFile,
    ULONG                Flags,
    PUNICODE_STRING      ModuleFileName,
    PHANDLE              ModuleHandle);

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

typedef HANDLE(WINAPI * FN_CreateThread)(
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId);

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

struct PARAM
{
    static const DWORD PARAM_ADDR = 0x10000000;
    static const DWORD PARAM_SIZE = 4096;
    LPVOID ntdllBase;
    LPVOID kernelBase;
    LPVOID kernel32;
    DWORD dwProcessId;
    DWORD dwThreadId;
    CONTEXT ctx;
    HANDLE NormalHeapHandle;
    HANDLE ExecuteHeapHandle;

    // ntdll
    FN_LdrInitializeThunk       f_LdrInitializeThunk;
    FN_LdrLoadDll               f_LdrLoadDll;

    // kernelbase
    FN_GetModuleHandleA         f_GetModuleHandleA;
    FN_GetProcAddress           f_GetProcAddress;
    FN_OpenThread               f_OpenThread;
    FN_SuspendThread            f_SuspendThread;
    FN_SetThreadContext         f_SetThreadContext;
    FN_ResumeThread             f_ResumeThread;
    FN_CloseHandle              f_CloseHandle;
    FN_CreateThread             f_CreateThread;
    FN_OutputDebugStringA       f_OutputDebugStringA;
    FN_VirtualAlloc             f_VirtualAlloc;
    FN_VirtualProtect           f_VirtualProtect;

    // kernel32
    FN_CreateToolhelp32Snapshot f_CreateToolhelp32Snapshot;
    FN_Module32First            f_Module32First;
    FN_Module32Next             f_Module32Next;
    FN_HeapCreate               f_HeapCreate;
    FN_HeapAlloc                f_HeapAlloc;
    FN_HeapFree                 f_HeapFree;
    FN_GetProcessHeap           f_GetProcessHeap;
    FN_CreateFileA              f_CreateFileA;
    FN_ReadFile                 f_ReadFile;
    FN_WriteFile                f_WriteFile;
    FN_WaitNamedPipeA           f_WaitNamedPipeA;
    FN_SetNamedPipeHandleState  f_SetNamedPipeHandleState;
    FN_GetLastError             f_GetLastError;
};