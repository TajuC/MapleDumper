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
    inline std::vector<MEMORY_BASIC_INFORMATION> GetMemoryRegions(HANDLE hProc, bool limitToModule, const std::string& moduleName) {
        std::vector<MEMORY_BASIC_INFORMATION> regions;
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
                                if (mbi.State == MEM_COMMIT) {
                                    DWORD p = mbi.Protect & 0xFF;
                                    if (p != PAGE_NOACCESS && p != PAGE_GUARD) {
                                        if (p & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
                                            MEMORY_BASIC_INFORMATION clipped = mbi;
                                            uintptr_t cStart = (std::max)(rStart, reinterpret_cast<uintptr_t>(me.modBaseAddr));
                                            uintptr_t cEnd = (std::min)(rEnd, end);
                                            if (cEnd > cStart) {
                                                clipped.BaseAddress = reinterpret_cast<PVOID>(cStart);
                                                clipped.RegionSize = cEnd - cStart;
                                                regions.push_back(clipped);
                                            }
                                        }
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
                if (mbi.State == MEM_COMMIT) {
                    DWORD p = mbi.Protect & 0xFF;
                    if (p != PAGE_NOACCESS && p != PAGE_GUARD) {
                        if (p & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) {
                            regions.push_back(mbi);
                        }
                    }
                }
                addr += mbi.RegionSize;
            }
        }
        return regions;
    }
}
