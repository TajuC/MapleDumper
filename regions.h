#pragma once
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>

namespace proc {
    inline bool IsReadableProtect(DWORD p) {
        p &= 0xFF;
        if (p == PAGE_NOACCESS || p == PAGE_GUARD) return false;
        return (p & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                     PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
    }

    inline std::vector<MEMORY_BASIC_INFORMATION> GetMemoryRegions(HANDLE hProc, bool limitToModule, const std::string& moduleName) {
        std::vector<MEMORY_BASIC_INFORMATION> regs;
        if (limitToModule) {
            MODULEENTRY32 me{};
            me.dwSize = sizeof(MODULEENTRY32);
            DWORD pid = GetProcessId(hProc);
            HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
            if (snap != INVALID_HANDLE_VALUE) {
                if (Module32First(snap, &me)) {
                    do {
                        if (_stricmp(me.szModule, moduleName.c_str()) == 0) {
                            uintptr_t cur = reinterpret_cast<uintptr_t>(me.modBaseAddr);
                            uintptr_t end = cur + me.modBaseSize;
                            while (cur < end) {
                                MEMORY_BASIC_INFORMATION mbi{};
                                if (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(cur), &mbi, sizeof(mbi)) != sizeof(mbi)) break;
                                uintptr_t rStart = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
                                uintptr_t rEnd = rStart + mbi.RegionSize;
                                if (mbi.State == MEM_COMMIT && IsReadableProtect(mbi.Protect)) {
                                    MEMORY_BASIC_INFORMATION clipped = mbi;
                                    uintptr_t cStart = (std::max)(rStart, reinterpret_cast<uintptr_t>(me.modBaseAddr));
                                    uintptr_t cEnd = (std::min)(rEnd, end);
                                    if (cEnd > cStart) {
                                        clipped.BaseAddress = reinterpret_cast<PVOID>(cStart);
                                        clipped.RegionSize = cEnd - cStart;
                                        regs.push_back(clipped);
                                    }
                                }
                                cur = rEnd;
                            }
                            break;
                        }
                    } while (Module32Next(snap, &me));
                }
                CloseHandle(snap);
            }
        } else {
            SYSTEM_INFO si{};
            GetSystemInfo(&si);
            uintptr_t addr = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
            uintptr_t maxAddr = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);
            while (addr < maxAddr) {
                MEMORY_BASIC_INFORMATION mbi{};
                if (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) != sizeof(mbi)) break;
                if (mbi.State == MEM_COMMIT && IsReadableProtect(mbi.Protect)) regs.push_back(mbi);
                addr += mbi.RegionSize;
            }
        }

        if (regs.empty()) return regs;

        std::sort(regs.begin(), regs.end(), [](const MEMORY_BASIC_INFORMATION& a, const MEMORY_BASIC_INFORMATION& b) {
            return reinterpret_cast<uintptr_t>(a.BaseAddress) < reinterpret_cast<uintptr_t>(b.BaseAddress);
        });

        std::vector<MEMORY_BASIC_INFORMATION> merged;
        merged.reserve(regs.size());
        MEMORY_BASIC_INFORMATION cur = regs[0];
        for (size_t i = 1; i < regs.size(); ++i) {
            MEMORY_BASIC_INFORMATION nxt = regs[i];
            uintptr_t curEnd = reinterpret_cast<uintptr_t>(cur.BaseAddress) + cur.RegionSize;
            if (curEnd == reinterpret_cast<uintptr_t>(nxt.BaseAddress) &&
                IsReadableProtect(cur.Protect) && IsReadableProtect(nxt.Protect)) {
                cur.RegionSize += nxt.RegionSize;
                if (nxt.Protect != cur.Protect) cur.Protect = PAGE_EXECUTE_READWRITE;
                continue;
            }
            merged.push_back(cur);
            cur = nxt;
        }
        merged.push_back(cur);
        return merged;
    }
}
