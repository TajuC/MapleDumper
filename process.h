#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <thread>
#include <iostream>

namespace proc {

    inline DWORD GetProcessIDByClass(const std::string& className) {
        DWORD pid = 0;
        while (!pid) {
            HWND hWnd = FindWindowA(className.c_str(), nullptr);
            if (hWnd)
                GetWindowThreadProcessId(hWnd, &pid);
            if (!pid) {
                std::cout << "Waiting for window class: " << className << "...\n";
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }
        return pid;
    }

    inline DWORD GetProcessIDByName(const std::string& processName) {
        DWORD pid = 0;
        while (!pid) {
            HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            if (hSnap != INVALID_HANDLE_VALUE) {
                PROCESSENTRY32 pe{};
                pe.dwSize = sizeof(PROCESSENTRY32);
                if (Process32First(hSnap, &pe)) {
                    do {
                        if (_stricmp(pe.szExeFile, processName.c_str()) == 0) {
                            pid = pe.th32ProcessID;
                            break;
                        }
                    } while (Process32Next(hSnap, &pe));
                }
                CloseHandle(hSnap);
            }
            if (!pid) {
                std::cout << "\rWaiting for process: " << processName << "... " << std::flush;
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }
        return pid;
    }

    inline HANDLE OpenTargetProcess(DWORD pid) {
        return OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    }

}
