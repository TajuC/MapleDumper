#pragma once
#include <Windows.h>
#include <cstdint>
#include <optional>
#include "ntapi.h"

namespace scan {

    class Reader {
    public:
        explicit Reader(core::nt::NtReadVirtualMemory_t fn) : _ntread(fn) {}

        bool Read(HANDLE proc, LPCVOID base, void* buffer, size_t size, size_t& read) const {
            if (!_ntread) return false;
            const auto status = _ntread(proc, const_cast<PVOID>(base), buffer,
                static_cast<ULONG>(size), reinterpret_cast<PULONG>(&read));
            return status >= 0;
        }

    private:
        core::nt::NtReadVirtualMemory_t _ntread;
    };

}
