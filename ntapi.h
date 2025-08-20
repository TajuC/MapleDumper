#pragma once
#include <Windows.h>
#include <winternl.h>
#include <optional>

namespace core::nt {

    using NtReadVirtualMemory_t = NTSTATUS(WINAPI*)(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        ULONG NumberOfBytesToRead,
        PULONG NumberOfBytesRead
        );

    inline std::optional<NtReadVirtualMemory_t> LoadNtReadVirtualMemory() {
        if (const auto hNtdll = ::GetModuleHandleA("ntdll.dll")) {
            if (const auto fn = reinterpret_cast<NtReadVirtualMemory_t>(
                GetProcAddress(hNtdll, "NtReadVirtualMemory")))
                return fn;
        }
        return std::nullopt;
    }

}
