#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <thread>
#include <chrono>
#include <iostream>

namespace proc {
    inline DWORD GetProcessIDByClass(const std::string& className) {
        DWORD pid = 0;
        while (!pid) {
            HWND hWnd = FindWindowA(className.c_str(), nullptr);
            if (hWnd) GetWindowThreadProcessId(hWnd, &pid);
            if (!pid) {
                std::cout << "\rWaiting for process (class): " << className << "..." << std::flush;
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
        }
        std::cout << "\nFound PID: " << pid << "\n";
        return pid;
    }

    inline DWORD GetProcessIDByName(const std::string& processName) {
        DWORD pid = 0;
        while (!pid) {
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe{};
                pe.dwSize = sizeof(pe);
                if (Process32First(hSnap, &pe)) {
                    do {
                        if (_stricmp(pe.szExeFile, processName.c_str()) == 0) { pid = pe.th32ProcessID; break; }
                    } while (Process32Next(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }
            if (!pid) {
                std::cout << "\rWaiting for process (name): " << processName << "..." << std::flush;
                std::this_thread::sleep_for(std::chrono::seconds(2));
            }
        }
        std::cout << "\nFound PID: " << pid << "\n";
        return pid;
    }

    inline bool EnableDebugPrivilege() {
        HANDLE hToken{};
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
        LUID luid{};
        if (!LookupPrivilegeValueA(nullptr, SE_DEBUG_NAME, &luid)) { CloseHandle(hToken); return false; }
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        bool ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
        CloseHandle(hToken);
        return ok && GetLastError() == ERROR_SUCCESS;
    }

    inline HANDLE OpenTargetProcess(DWORD pid) {
        EnableDebugPrivilege();
        const DWORD tryRights[] = {
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
        };
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        HANDLE h{};
        while (std::chrono::steady_clock::now() < deadline) {
            for (DWORD rights : tryRights) {
                h = OpenProcess(rights, FALSE, pid);
                if (h) return h;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        return nullptr;
    }
}