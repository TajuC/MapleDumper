#pragma once
#include <Windows.h>
#include <winternl.h>
#include <optional>

namespace core::nt {
    using NtReadVirtualMemory_t = NTSTATUS(WINAPI*)(HANDLE, PVOID, PVOID, ULONG, PULONG);

    inline std::optional<NtReadVirtualMemory_t> LoadNtReadVirtualMemory() {
        HMODULE h = GetModuleHandleA("ntdll.dll");
        if (!h) h = LoadLibraryA("ntdll.dll");
        if (!h) return std::nullopt;
        auto fn = reinterpret_cast<NtReadVirtualMemory_t>(GetProcAddress(h, "NtReadVirtualMemory"));
        if (!fn) fn = reinterpret_cast<NtReadVirtualMemory_t>(GetProcAddress(h, "ZwReadVirtualMemory"));
        if (!fn) return std::nullopt;
        return fn;
    }
}