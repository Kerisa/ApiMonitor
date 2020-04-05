
#include "allocator.h"

namespace Allocator
{
#ifdef PAYLOAD
    void InitAllocator()
    {
        // CeateHeap
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        param->NormalHeapHandle = param->f_HeapCreate(0, 1024 * 1024 * 10, 0);
        param->ExecuteHeapHandle = param->f_HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, 1024 * 1024 * 1, 0);
    }

    void* MallocExe(size_t s)
    {
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        return param->f_HeapAlloc(param->ExecuteHeapHandle, 0, s);
    }

    void FreeExe(void* ptr)
    {
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        param->f_HeapFree(param->ExecuteHeapHandle, 0, ptr);
    }

    void* Malloc(size_t s)
    {
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        return param->f_HeapAlloc(param->NormalHeapHandle, 0, s);
    }

    void Free(void* ptr)
    {
        PARAM *param = (PARAM*)(LPVOID)PARAM::PARAM_ADDR;
        param->f_HeapFree(param->NormalHeapHandle, 0, ptr);
    }
#endif
}