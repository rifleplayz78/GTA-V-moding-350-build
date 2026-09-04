// https://github.com/CamxxCore/PauseMenuHelper/blob/master/PauseMenuHelper/Hooking.h

#pragma once

#include <windows.h>
#include <inttypes.h>

template <typename T>
class Hook
{
public:
    Hook(void* addr, T func) : address((BYTE*)addr), fn(func) {}
    virtual ~Hook() {}
    virtual void remove() = 0;

    BYTE* address;
    T fn;
};

template <typename T>
class CallHook : public Hook<T>
{
public:
    CallHook(void* addr, T func) : Hook<T>(addr, func) {}
    ~CallHook() { remove(); }

    virtual void remove()
    {
        // restore original call instruction
        *reinterpret_cast<int32_t*>(this->address + 1) =
            static_cast<int32_t>((intptr_t)this->fn - (intptr_t)this->address - 5);
    }
};

class HookManager
{
public:
    template <typename T>
    static CallHook<T>* SetCall(char* address, T func)
    {
        // Get original function target
        T target = reinterpret_cast<T>(
            *reinterpret_cast<int32_t*>(address + 1) + (intptr_t)(address + 5)
            );

        // Allocate stub
        auto pFunc = AllocateFunctionStub(GetModuleHandle(nullptr), (PVOID)func, 0);

        // Write the call opcode
        *(BYTE*)address = 0xE8;

        // Write relative offset
        *reinterpret_cast<int32_t*>(address + 1) =
            (int32_t)((intptr_t)pFunc - (intptr_t)address - 5);

        return new CallHook<T>(address, target);
    }

    static PVOID AllocateFunctionStub(PVOID origin, PVOID function, int type);
    static LPVOID FindPrevFreeRegion(LPVOID pAddress, LPVOID pMinAddr, DWORD gran);
};
