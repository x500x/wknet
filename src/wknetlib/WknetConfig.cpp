#include <wknet/WknetConfig.h>
#include <wknet/core/Lookaside.h>

#if !defined(WKNET_USER_MODE_TEST)

_Ret_maybenull_
void* __cdecl operator new(size_t size)
{
    return wknet::AllocateNonPagedPoolBytes(size);
}

_Ret_maybenull_
void* __cdecl operator new[](size_t size)
{
    return wknet::AllocateNonPagedPoolBytes(size);
}

void __cdecl operator delete(void* pointer) noexcept
{
    wknet::FreeNonPagedPoolBytes(pointer);
}

void __cdecl operator delete[](void* pointer) noexcept
{
    wknet::FreeNonPagedPoolBytes(pointer);
}

void __cdecl operator delete(void* pointer, size_t size) noexcept
{
    UNREFERENCED_PARAMETER(size);
    operator delete(pointer);
}

void __cdecl operator delete[](void* pointer, size_t size) noexcept
{
    UNREFERENCED_PARAMETER(size);
    operator delete[](pointer);
}

#endif
