

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef NTSTATUS(NTAPI * FN_LdrLoadDll)(
    PWCHAR               PathToFile OPTIONAL,
    ULONG                Flags OPTIONAL,
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

struct PARAM
{
    static const DWORD PARAM_ADDR = 0x10000000;
    static const DWORD PARAM_SIZE = 4096;
    LPVOID ntdllBase;
    LPVOID kernelBase;
    DWORD dwProcessId;
    DWORD dwThreadId;
    CONTEXT ctx;

    FN_GetProcAddress   f_GetProcAddress;
    FN_OpenThread       f_OpenThread;
    FN_SuspendThread    f_SuspendThread;
    FN_SetThreadContext f_SetThreadContext;
    FN_ResumeThread     f_ResumeThread;
    FN_CloseHandle      f_CloseHandle;
    FN_CreateThread     f_CreateThread;
};