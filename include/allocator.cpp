
#include "allocator.h"

namespace Allocator
{
#ifdef PAYLOAD
    void InitAllocator()
    {
        // CeateHeap
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        // 16 ×Ö½Ú¶ÔÆëÐ»Ð»
        __declspec(align(16)) SIZE_T RegionSize = 16 * 1024 * 1024;
        __declspec(align(16)) LPVOID BaseAddress = 0;
        param->NormalHeapHandle = param->f_RtlCreateHeap(HEAP_GROWABLE, BaseAddress, RegionSize, 0, 0, 0);

        RegionSize = 4 * 1024 * 1024;
        BaseAddress = 0;
        //param->f_NtAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &RegionSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        param->ExecuteHeapHandle = param->f_RtlCreateHeap(HEAP_CREATE_ENABLE_EXECUTE | HEAP_GROWABLE, BaseAddress, RegionSize, 0, 0, 0);
    }

    void* MallocExe(size_t s)
    {
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        return param->f_RtlAllocateHeap(param->ExecuteHeapHandle, 0, s);
    }

    void FreeExe(void* ptr)
    {
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        param->f_RtlFreeHeap(param->ExecuteHeapHandle, 0, ptr);
    }

    void* Malloc(size_t s)
    {
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        return param->f_RtlAllocateHeap(param->NormalHeapHandle, 0, s);
    }

    void Free(void* ptr)
    {
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        param->f_RtlFreeHeap(param->NormalHeapHandle, 0, ptr);
    }
#endif
}